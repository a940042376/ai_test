import http from 'http'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const ROOT_DIR = path.join(__dirname, '..')
const PORT = process.env.DEPLOY_RUN_PORT || 5000

interface Issue {
  line: number
  severity: 'error' | 'warning' | 'info'
  category: 'security' | 'performance' | 'best-practice' | 'norms' | 'runtime'
  message: string
  suggestion: string
  beforeCode?: string
  afterCode?: string
}

const JAVA_RULES: any[] = [
  // ===== SQL 注入 =====
  {
    pattern: /SELECT\s+\*\s+FROM.*WHERE.*\+\s*\w+/gi,
    severity: 'error',
    category: 'security',
    message: 'SQL 注入风险：字符串拼接方式构建 SQL 查询',
    suggestion: '使用 PreparedStatement 的参数化查询，或使用 ORM 框架的参数绑定功能。',
    beforeCode: `String query = "SELECT * FROM users WHERE id = " + id;
stmt.executeQuery(query);`,
    afterCode: `// 使用 PreparedStatement
String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setLong(1, id);
ResultSet rs = ps.executeQuery();

// 或使用 MyBatis
@Select("SELECT * FROM users WHERE id = #{id}")
User findById(Long id);`,
  },
  {
    pattern: /\.executeQuery\(.*\+\s*\w+/g,
    severity: 'error',
    category: 'security',
    message: 'SQL 注入风险：动态拼接 SQL 语句',
    suggestion: '使用参数化查询代替字符串拼接。',
    beforeCode: `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);`,
    afterCode: `PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
ps.setLong(1, userId);
ResultSet rs = ps.executeQuery();`,
  },

  // ===== 资源泄漏 =====
  {
    pattern: /Connection\s+\w+\s*=.*\.getConnection\(\)[\s\S]*?(?=\n\s*(?:public|private|protected|class|$))/gi,
    severity: 'error',
    category: 'performance',
    message: '资源泄漏：数据库连接可能未正确关闭',
    suggestion: '使用 try-with-resources 确保资源正确关闭。',
    beforeCode: `Connection conn = dataSource.getConnection();
PreparedStatement ps = conn.prepareStatement(sql);
ResultSet rs = ps.executeQuery();
// 没有关闭连接`,
    afterCode: `// try-with-resources 自动关闭
try (Connection conn = dataSource.getConnection();
     PreparedStatement ps = conn.prepareStatement(sql)) {
    ResultSet rs = ps.executeQuery();
    // 处理结果
} // 自动关闭`,
  },

  // ===== 运行时异常 =====
  {
    pattern: /\w+\s*\/\s*0\s*;|\w+\s*\/\s*\$\{|[\d\.\w]+\s*\/\s*\(.*0.*\)[\s\;\)\}]/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：除零错误 (ArithmeticException)',
    suggestion: '在除法运算前检查除数是否为零。',
    beforeCode: `int result = a / b;  // 如果 b=0 会抛出 ArithmeticException
int A = 10 / 0;  // 直接除零`,
    afterCode: `// 检查除数
if (b != 0) {
    int result = a / b;
} else {
    // 处理除数为零的情况
    throw new IllegalArgumentException("除数不能为零");
}

// 或使用 Optional
int result = Optional.ofNullable(divisor)
    .filter(d -> d != 0)
    .map(d -> dividend / d)
    .orElseThrow(() -> new ArithmeticException("除数不能为零"));`,
  },
  {
    pattern: /\bint\b.*\[\s*\]|int\s+\w+\s*\[.*\]\s*=/gi,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：数组声明缺少长度',
    suggestion: '数组必须指定长度才能使用。',
    beforeCode: `int[] arr = new int[];  // 错误：缺少长度
arr[0] = 1;`,
    afterCode: `// 方案1：指定长度
int[] arr = new int[10];

// 方案2：直接初始化
int[] arr = {1, 2, 3, 4, 5};

// 方案3：动态大小用 ArrayList
List<Integer> list = new ArrayList<>();`,
  },
  {
    pattern: /new\s+\w+\(rs\.getString\(/gi,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：空指针风险 (NullPointerException)',
    suggestion: 'ResultSet.getString() 可能返回 null，直接使用可能导致 NPE。',
    beforeCode: `User user = new User(rs.getString("name"));  // 可能 NPE
String name = rs.getString("name").trim();  // NPE`,
    afterCode: `// 安全方式1：使用 Optional
String name = Optional.ofNullable(rs.getString("name"))
    .map(String::trim)
    .orElse("");

// 安全方式2：空值检查
String name = rs.getString("name");
if (name != null) {
    user.setName(name.trim());
}

// 安全方式3：使用三目运算符
String name = rs.getString("name") != null ? rs.getString("name") : "";`,
  },
  {
    pattern: /\[\s*\w+\s*\]\s*\[\s*0\s*\]|\[\s*\d+\s*\]\[\s*\w+\s*\]|\.get\(.*-\d+.*\)/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：数组越界 (ArrayIndexOutOfBoundsException)',
    suggestion: '访问数组元素前确保索引在有效范围内 (0 到 length-1)。',
    beforeCode: `int[] arr = new int[5];
int x = arr[5];  // 越界！有效索引是 0-4
int y = arr[-1];  // 负数索引也无效`,
    afterCode: `int[] arr = new int[5];

// 安全访问方式1：检查边界
if (index >= 0 && index < arr.length) {
    int x = arr[index];
}

// 安全访问方式2：使用 Optional 或默认值
int x = IntStream.range(0, arr.length)
    .filter(i -> i == index)
    .findFirst()
    .map(i -> arr[i])
    .orElse(0);

// 安全访问方式3：使用 ArrayList
List<Integer> list = new ArrayList<>();
int x = list.get(index);  // 有边界检查，超界抛异常`,
  },
  {
    pattern: /\(int\)\s*\(\s*\w+\.\w+\s*\)|\(String\)\s*\d+|Integer\.parseInt\([^\)]*\)/gi,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：类型转换错误 (ClassCastException)',
    suggestion: '进行类型转换前使用 instanceof 检查对象类型。',
    beforeCode: `Object obj = "123";
int num = (int) obj;  // ClassCastException

Object numObj = 123;
String str = (String) numObj;  // ClassCastException`,
    afterCode: `// 安全类型转换
Object obj = "123";

// 使用 instanceof 检查
if (obj instanceof String) {
    String str = (String) obj;
}

// 使用 Optional 安全转换
Optional<Integer> num = Optional.ofNullable(obj)
    .filter(Integer.class::isInstance)
    .map(Integer.class::cast);

// 使用 try-catch
try {
    int num = Integer.parseInt(obj.toString());
} catch (NumberFormatException e) {
    // 处理转换失败
}`,
  },
  {
    pattern: /List<\w+>\s+\w+\s*=\s*null|Map<\w+,\s*\w+>\s+\w+\s*=\s*null|Set<\w+>\s+\w+\s*=\s*null/gi,
    severity: 'warning',
    category: 'runtime',
    message: '运行时异常：集合初始化为 null 可能导致 NPE',
    suggestion: '使用空集合代替 null，避免 NullPointerException。',
    beforeCode: `List<String> list = null;
list.add("item");  // NullPointerException!`,
    afterCode: `// 使用空集合
List<String> list = Collections.emptyList();

// 或使用 ArrayList
List<String> list = new ArrayList<>();
list.add("item");  // 安全

// 如果需要可空，使用 Optional
Optional<List<String>> listOpt = Optional.ofNullable(possiblyNullList);`,
  },
  {
    pattern: /\w+\[\s*\]/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：访问空数组导致 ArrayIndexOutOfBoundsException',
    suggestion: '确保数组已正确初始化且长度大于 0。',
    beforeCode: `String[] arr = null;
String first = arr[0];  // NullPointerException
System.out.println(arr.length);  // NullPointerException`,
    afterCode: `// 安全方式
String[] arr = new String[0];

// 或
String[] arr = {"a", "b"};

// 访问前检查
if (arr != null && arr.length > 0) {
    String first = arr[0];
}

// 使用 Optional
Optional<String> first = Arrays.stream(arr)
    .findFirst();`,
  },

  // ===== 命名规范 =====
  {
    pattern: /\b(int|long|double|float|boolean|String)\s+[A-Z][A-Za-z0-9]*\s*[=;]/g,
    severity: 'error',
    category: 'norms',
    message: '命名规范：变量名不能以大写字母开头',
    suggestion: 'Java 变量命名应使用小写字母开头（camelCase）。',
    beforeCode: `int Number = 10;  // 错误
String Name = "Tom";  // 错误
double Price = 99.9;  // 错误`,
    afterCode: `// 正确：使用小写开头
int number = 10;
String name = "Tom";
double price = 99.9;

// 常量除外（大写+下划线）
static final int MAX_COUNT = 100;`,
  },
  {
    pattern: /\bstatic\s+final\s+[a-z][a-zA-Z0-9]*\s*=/g,
    severity: 'warning',
    category: 'norms',
    message: '命名规范：常量命名应使用大写字母和下划线',
    suggestion: 'Java 常量命名应使用全大写，单词间用下划线分隔（SNAKE_CASE）。',
    beforeCode: `static final int maxCount = 100;  // 错误
static final String tableName = "users";  // 错误`,
    afterCode: `// 正确：使用大写+下划线
static final int MAX_COUNT = 100;
static final String TABLE_NAME = "users";

// 枚举常量
static final String ORDER_STATUS_PENDING = "pending";`,
  },
  {
    pattern: /\b(class|interface|enum)\s+[a-z][a-zA-Z0-9]*\s*[{<(]/gi,
    severity: 'error',
    category: 'norms',
    message: '命名规范：类/接口/枚举名必须以大写字母开头',
    suggestion: 'Java 类型命名应使用大写字母开头（PascalCase）。',
    beforeCode: `class userService { }  // 错误
interface database { }  // 错误
enum orderStatus { }  // 错误`,
    afterCode: `// 正确：使用大写开头
class UserService { }
interface Database { }
enum OrderStatus { }
abstract class BaseController { }`,
  },
  {
    pattern: /\bmethod\s+\w+|\bfunction\s+\w+/gi,
    severity: 'warning',
    category: 'norms',
    message: '命名规范：方法名应使用小写字母开头',
    suggestion: 'Java 方法命名应使用小写字母开头（camelCase）。',
    beforeCode: `void GetUser() { }  // 错误
void calculateTotal() { }  // 可接受
public User FindById() { }  // 建议改为 findById`,
    afterCode: `// 正确：使用小写开头
void getUser() { }
void calculateTotal() { }
public User findById() { }
public List<Order> findByStatus() { }`,
  },
  {
    pattern: /\b_\w+|\w+_\s*[=;]/g,
    severity: 'info',
    category: 'norms',
    message: '命名规范：避免使用下划线开头或结尾的变量名',
    suggestion: 'Java 变量名通常不使用下划线（除常量外）。',
    beforeCode: `int _count = 0;
String name_ = "Tom";
double _price = 99.9;`,
    afterCode: `// 正确：使用驼峰命名
int count = 0;
String name = "Tom";
double price = 99.9;

// 常量可以使用下划线
static final int MAX_COUNT = 100;`,
  },
  {
    pattern: /\b[a-z][a-z0-9]{0,2}\b\s*=/gi,
    severity: 'info',
    category: 'norms',
    message: '命名规范：变量名过短，建议使用更有意义的名称',
    suggestion: '使用完整、有意义的单词或缩写作为变量名，提高代码可读性。',
    beforeCode: `int a = 0;  // 太短
String n = "name";  // 不明确
double p = 99.9;  // 不明确`,
    afterCode: `// 正确：使用有意义的名称
int count = 0;
String userName = "name";
double price = 99.9;
double totalPrice = price * quantity;`,
  },

  // ===== 代码风格 =====
  {
    pattern: /System\.out\.print/g,
    severity: 'info',
    category: 'norms',
    message: '代码规范：不应使用 System.out 进行日志输出',
    suggestion: '使用专业的日志框架（SLF4J + Logback）替代 System.out。',
    beforeCode: `System.out.println("User logged in: " + username);
System.err.println("Error: " + message);`,
    afterCode: `// 使用 SLF4J + Logback
private static final Logger log = LoggerFactory.getLogger(UserService.class);

log.info("User logged in: {}", username);
log.error("Error: {}", message, e);`,
  },
  {
    pattern: /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}/gi,
    severity: 'warning',
    category: 'best-practice',
    message: '代码规范：捕获空异常块',
    suggestion: '至少记录异常日志，或根据业务需求进行适当处理。',
    beforeCode: `try {
    // some code
} catch (Exception e) {
}  // 空异常块，异常被忽略`,
    afterCode: `try {
    // some code
} catch (Exception e) {
    log.error("操作失败: {}", e.getMessage(), e);
    throw new BusinessException("操作失败");
}

// 或明确忽略
try {
    // 非关键操作
} catch (Exception ignored) {
    // 记录审计日志
}`,
  },
  {
    pattern: /\+\s*""\s*\+|\+\s*''\s*\+/g,
    severity: 'warning',
    category: 'norms',
    message: '代码规范：字符串拼接时避免空字符串连接',
    suggestion: '简化字符串拼接，移除不必要的空字符串。',
    beforeCode: `String result = "" + num;  // 多余的空字符串
String msg = "Hello " + "" + name + "";`,
    afterCode: `// 简化
String result = String.valueOf(num);
String msg = "Hello " + name;

// 或使用 String.valueOf
String result = num + "";  // 不推荐
String result = String.valueOf(num);  // 推荐`,
  },
  {
    pattern: /==\s*(?:true|false)/gi,
    severity: 'info',
    category: 'norms',
    message: '代码规范：布尔值与 true/false 的冗余比较',
    suggestion: '直接使用布尔表达式。',
    beforeCode: `if (isValid == true) { ... }
if (hasError == false) { ... }`,
    afterCode: `if (isValid) { ... }
if (!hasError) { ... }`,
  },
  {
    pattern: /ArrayList\s*<.*>\s*\w+\s*=\s*new\s+ArrayList/gi,
    severity: 'info',
    category: 'norms',
    message: '代码规范：使用接口类型声明变量',
    suggestion: '使用 List 接口类型声明变量，便于替换实现类。',
    beforeCode: `ArrayList<User> users = new ArrayList<>();`,
    afterCode: `// 推荐：使用接口类型
List<User> users = new ArrayList<>();

// 如果需要指定初始容量
List<User> users = new ArrayList<>(expectedSize);`,
  },
  {
    pattern: /new\s+Date\(\)/gi,
    severity: 'info',
    category: 'norms',
    message: '代码规范：使用 Instant 或 LocalDateTime 替代 Date',
    suggestion: 'Java 8+ 推荐使用 Instant、LocalDateTime 等新日期时间 API。',
    beforeCode: `Date now = new Date();
Date date = new Date(timestamp);`,
    afterCode: `// 使用 Java 8+ 日期时间 API
Instant now = Instant.now();
LocalDateTime dateTime = LocalDateTime.now();
LocalDate date = LocalDate.now();

// 格式化
String formatted = LocalDateTime.now().format(
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));`,
  },
  {
    pattern: /if\s*\(\s*\w+\s*==\s*null\s*\)/gi,
    severity: 'info',
    category: 'norms',
    message: '代码规范：考虑使用卫语句提前返回，减少嵌套',
    suggestion: '先处理空值情况，减少嵌套层级。',
    beforeCode: `if (user != null) {
    if (order != null) {
        if (product != null) {
            // 核心逻辑
        }
    }
}`,
    afterCode: `// 卫语句提前返回
if (user == null) return;
if (order == null) return;
if (product == null) return;

// 核心逻辑在前面，正常流程更清晰`,
  },
]

const MYSQL_RULES: any[] = [
  {
    pattern: /SELECT\s+\*/gi,
    severity: 'warning',
    category: 'performance',
    message: '性能问题：SELECT * 可能导致性能下降',
    suggestion: '明确指定需要的列名，避免不必要的数据传输。',
    beforeCode: `SELECT * FROM users WHERE id = 1;
SELECT * FROM orders WHERE status = 'pending';`,
    afterCode: `-- 只查询需要的字段
SELECT id, username, email FROM users WHERE id = 1;`,
  },
  {
    pattern: /FROM\s+\w+\s*,\s*\w+\s*(?:WHERE|ORDER|GROUP|LIMIT|$)/gi,
    severity: 'warning',
    category: 'best-practice',
    message: 'SQL 规范：使用隐式连接（逗号分隔表）',
    suggestion: '使用显式 JOIN 语法，使查询意图更清晰。',
    beforeCode: `SELECT * FROM orders, customers 
WHERE orders.customer_id = customers.id;`,
    afterCode: `-- 显式 INNER JOIN
SELECT o.*, c.name as customer_name
FROM orders o
INNER JOIN customers c ON o.customer_id = c.id;`,
  },
  {
    pattern: /WHERE.*!=\s*\w+|WHERE.*<>\s*\w+/gi,
    severity: 'warning',
    category: 'performance',
    message: '性能问题：不等于查询可能无法使用索引',
    suggestion: '考虑是否可以用其他方式表达逻辑。',
    beforeCode: `SELECT * FROM users WHERE status != 'deleted';`,
    afterCode: `-- 使用 IN
SELECT * FROM users WHERE status IN ('active', 'pending');`,
  },
  {
    pattern: /LIMIT\s+\d+\s*,\s*\d+|\bLIMIT\s+\d+\s+OFFSET\s+\d+/gi,
    severity: 'warning',
    category: 'performance',
    message: '性能问题：大偏移量分页导致性能问题',
    suggestion: '使用基于主键的游标分页替代 OFFSET 分页。',
    beforeCode: `-- 传统 OFFSET 分页，越往后越慢
SELECT * FROM orders LIMIT 10 OFFSET 100000;`,
    afterCode: `-- 游标分页：利用主键索引，性能稳定
SELECT * FROM orders WHERE id > #{last_id} ORDER BY id LIMIT 10;`,
  },
  {
    pattern: /password\s+FROM|passwd\s+FROM|pwd\s+FROM|secret\s+FROM|token\s+FROM/gi,
    severity: 'error',
    category: 'security',
    message: '安全风险：直接查询敏感字段',
    suggestion: '不要在查询中返回敏感字段。',
    beforeCode: `SELECT id, username, password FROM users WHERE id = 1;`,
    afterCode: `-- 只查询必要字段
SELECT id, username FROM users WHERE username = ?;
// 在应用层验证密码哈希`,
  },
  {
    pattern: /INSERT\s+INTO\s+\w+\s*VALUES\s*\(/gi,
    severity: 'info',
    category: 'norms',
    message: 'SQL 规范：INSERT 语句未指定列名',
    suggestion: '明确指定插入的列名，便于维护。',
    beforeCode: `INSERT INTO users VALUES (1, 'Tom', 'tom@example.com');`,
    afterCode: `-- 明确指定列名
INSERT INTO users (id, username, email) 
VALUES (1, 'Tom', 'tom@example.com');`,
  },
  {
    pattern: /DROP\s+TABLE\s+\w+(?!\s+IF\s+EXISTS)/gi,
    severity: 'warning',
    category: 'norms',
    message: 'SQL 规范：DROP TABLE 未使用 IF EXISTS',
    suggestion: '使用 DROP TABLE IF EXISTS 避免错误。',
    beforeCode: `DROP TABLE users;`,
    afterCode: `DROP TABLE IF EXISTS users;`,
  },
  {
    pattern: /CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)/gi,
    severity: 'info',
    category: 'norms',
    message: 'SQL 规范：CREATE TABLE 未使用 IF NOT EXISTS',
    suggestion: '使用 CREATE TABLE IF NOT EXISTS 避免重复创建。',
    beforeCode: `CREATE TABLE users (id BIGINT PRIMARY KEY);`,
    afterCode: `CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL COMMENT '用户名'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;`,
  },
  {
    pattern: /\bINT\b(?!\s*\()/gi,
    severity: 'info',
    category: 'norms',
    message: 'SQL 规范：建议使用 BIGINT 代替 INT 存储主键',
    suggestion: 'BIGINT 可存储更大范围数值，避免 int 溢出。',
    beforeCode: `CREATE TABLE orders (
    id INT PRIMARY KEY,  -- 最大约21亿
    ...
);`,
    afterCode: `CREATE TABLE orders (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,  -- 支持更大范围
    ...
);`,
  },
]

function analyzeCode(code: string, language: 'java' | 'mysql'): Issue[] {
  const rules = language === 'java' ? JAVA_RULES : MYSQL_RULES
  const issues: Issue[] = []
  const lines = code.split('\n')

  // 行级分析
  lines.forEach((line, index) => {
    const lineNum = index + 1
    const trimmedLine = line.trim()

    // 特殊检测：变量大写命名
    if (language === 'java') {
      // 检测 int A = 10/0 类型的错误
      const varWithDivide = line.match(/(int|long|double|float)\s+([A-Z][A-Za-z0-9_]*)\s*=\s*[^;]*\/[^;]*;/g)
      if (varWithDivide) {
        varWithDivide.forEach(match => {
          const varMatch = match.match(/(int|long|double|float)\s+([A-Z][A-Za-z0-9_]*)\s*=/)
          if (varMatch && varMatch[2]) {
            // 大写变量名
            issues.push({
              line: lineNum,
              severity: 'error',
              category: 'norms',
              message: `命名规范：变量 "${varMatch[2]}" 不应使用大写字母开头`,
              suggestion: 'Java 变量命名应使用小写字母开头（camelCase）。',
              beforeCode: `${varMatch[1]} ${varMatch[2]} = ...;`,
              afterCode: `${varMatch[1]} ${varMatch[2].charAt(0).toLowerCase() + varMatch[2].slice(1)} = ...;`,
            })
          }

          // 检测除零
          if (match.includes('/ 0') || match.includes('/0') || match.match(/\/\s*\d*\s*0\s*[\;\)]/)) {
            const type = line.match(/(int|long|double|float)\s+[A-Za-z]+\s*=/)?.[1] || '变量'
            issues.push({
              line: lineNum,
              severity: 'error',
              category: 'runtime',
              message: `运行时异常：除法运算可能导致 ArithmeticException (除零错误)`,
              suggestion: '在除法运算前检查除数是否为零。',
              beforeCode: match,
              afterCode: `// 检查除数是否为零
if (divisor != 0) {
    ${match.replace(/;\s*$/, '')}
} else {
    throw new ArithmeticException("除数不能为零");
}`,
            })
          }
        })
      }

      // 检测直接除零
      if (trimmedLine.match(/\/\s*0\s*[;\)]/) && !trimmedLine.startsWith('//') && !trimmedLine.startsWith('*')) {
        const hasComment = trimmedLine.match(/^\s*\/\//)
        if (!hasComment) {
          issues.push({
            line: lineNum,
            severity: 'error',
            category: 'runtime',
            message: '运行时异常：除零错误 (ArithmeticException)',
            suggestion: '除数不能为零，请检查运算逻辑。',
            beforeCode: trimmedLine,
            afterCode: `// 添加除零检查
if (divisor != 0) {
    ${trimmedLine.replace(/;$/, '')}
} else {
    // 处理除零情况
}`,
          })
        }
      }

      // 检测 null 方法调用
      if (trimmedLine.includes('.') && (trimmedLine.includes('null.') || trimmedLine.match(/\w+\.get\w+\(/))) {
        // 空指针风险检测
        const npMatch = trimmedLine.match(/(\w+)\.get(\w+)\((.*?)\)/g)
        if (npMatch && !trimmedLine.includes('Optional')) {
          issues.push({
            line: lineNum,
            severity: 'warning',
            category: 'runtime',
            message: '运行时异常：Map/List.get() 可能抛出异常',
            suggestion: '使用前检查 key 是否存在，或使用 Optional 处理。',
            beforeCode: trimmedLine,
            afterCode: `// 安全访问方式
if (map.containsKey(key)) {
    ${trimmedLine}
}
// 或使用 Optional
Optional.ofNullable(map.get(key)).orElse(defaultValue);`,
          })
        }
      }

      // 检测数组越界访问
      if (trimmedLine.match(/\[\s*[\w\d]+\s*\]\s*=/)) {
        const arrMatch = trimmedLine.match(/(\w+)\[/)
        if (arrMatch && arrMatch[1]) {
          // 检查数组是否已声明
          const arrName = arrMatch[1]
          const arrDeclare = lines.slice(0, index).some(l => 
            l.includes(arrName + ' = new') && (l.includes('[]') || l.includes('ArrayList'))
          )
          if (!arrDeclare) {
            issues.push({
              line: lineNum,
              severity: 'warning',
              category: 'runtime',
              message: `运行时异常：数组 "${arrName}" 可能未初始化`,
              suggestion: '确保数组已正确初始化。',
              beforeCode: trimmedLine,
              afterCode: `${arrName} = new int[size];  // 先初始化数组
${trimmedLine}`,
            })
          }
        }
      }
    }

    // 使用规则匹配
    rules.forEach((rule: any) => {
      if (rule.pattern && trimmedLine.match(rule.pattern)) {
        if (!issues.some(i => i.line === lineNum && i.message === rule.message)) {
          issues.push({
            line: lineNum,
            severity: rule.severity,
            category: rule.category,
            message: rule.message,
            suggestion: rule.suggestion,
            beforeCode: rule.beforeCode,
            afterCode: rule.afterCode,
          })
        }
      }
    })
  })

  return issues.sort((a, b) => a.line - b.line)
}

const server = http.createServer((req, res) => {
  const url = req.url || '/'

  if (req.method === 'POST' && url === '/api/code-review') {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      try {
        const { code, language } = JSON.parse(body)
        if (!code || !language) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Missing required fields' }))
          return
        }
        if (!['java', 'mysql'].includes(language)) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Invalid language' }))
          return
        }
        setTimeout(() => {
          const issues = analyzeCode(code, language)
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            issues,
            summary: {
              total: issues.length,
              errors: issues.filter((i: Issue) => i.severity === 'error').length,
              warnings: issues.filter((i: Issue) => i.severity === 'warning').length,
              suggestions: issues.filter((i: Issue) => i.severity === 'info').length,
            },
            timestamp: new Date().toISOString(),
          }))
        }, 400 + Math.random() * 400)
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Internal server error' }))
      }
    })
    return
  }

  let filePath = url === '/' ? '/index.html' : url
  filePath = path.join(ROOT_DIR, filePath)
  const ext = path.extname(filePath)
  const contentTypes: Record<string, string> = {
    '.html': 'text/html', '.js': 'application/javascript',
    '.css': 'text/css', '.json': 'application/json',
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      fs.readFile(path.join(ROOT_DIR, 'index.html'), (err2, data2) => {
        if (err2) {
          res.writeHead(404)
          res.end('Not Found')
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' })
          res.end(data2)
        }
      })
    } else {
      res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'text/plain' })
      res.end(data)
    }
  })
})

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
