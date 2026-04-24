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
  category: 'security' | 'performance' | 'best-practice' | 'norms'
  message: string
  suggestion: string
  beforeCode?: string
  afterCode?: string
}

const JAVA_RULES = [
  {
    pattern: /SELECT\s+\*\s+FROM.*WHERE.*\+\s*\w+/gi,
    severity: 'error' as const,
    category: 'security' as const,
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
    pattern: /Statement\s+\w+\s*=\s*\w+\.createStatement\(\)/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '使用 Statement 而非 PreparedStatement',
    suggestion: 'PreparedStatement 有预编译缓存，提高性能且防止 SQL 注入。',
    beforeCode: `Statement stmt = connection.createStatement();
String sql = "SELECT * FROM users WHERE name = '" + name + "'";
ResultSet rs = stmt.executeQuery(sql);`,
    afterCode: `PreparedStatement ps = connection.prepareStatement(
    "SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();`,
  },
  {
    pattern: /\.executeQuery\(.*\+\s*\w+/g,
    severity: 'error' as const,
    category: 'security' as const,
    message: 'SQL 注入风险：动态拼接 SQL 语句',
    suggestion: '使用参数化查询代替字符串拼接。',
    beforeCode: `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);`,
    afterCode: `PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ?");
ps.setLong(1, userId);
ResultSet rs = ps.executeQuery();`,
  },
  {
    pattern: /new\s+\w+\(rs\.getString\(/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: '空指针风险：ResultSet.getString() 可能返回 null',
    suggestion: '使用 Optional 或空值检查避免 NPE。',
    beforeCode: `User user = new User(rs.getString("name"));`,
    afterCode: `// 方式1：使用 Optional
String name = Optional.ofNullable(rs.getString("name"))
    .orElse("");

// 方式2：空值检查
String name = rs.getString("name");
if (name != null) {
    user.setName(name);
}

// 方式3：MyBatis/JPA 自动处理
@Result(property = "name", column = "name")
private String name;`,
  },
  {
    pattern: /Connection\s+\w+\s*=.*\.getConnection\(\)[\s\S]*?(?=public|private|protected|class|\n\n|$)/gi,
    severity: 'error' as const,
    category: 'performance' as const,
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
} // 自动关闭，无需手动 close()`,
  },
  {
    pattern: /System\.out\.print/g,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '日志规范：不应使用 System.out 进行日志输出',
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
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: '异常处理：捕获空异常块',
    suggestion: '至少记录异常日志，或根据业务需求进行适当处理。',
    beforeCode: `try {
    // some code
} catch (Exception e) {
}`,
    afterCode: `try {
    // some code
} catch (Exception e) {
    log.error("操作失败: {}", e.getMessage(), e);
    throw new BusinessException("操作失败，请稍后重试");
}

// 或根据业务场景吞掉异常
try {
    // 非关键操作，失败不影响主流程
} catch (Exception ignored) {
    // 记录审计日志
    log.warn("非关键操作失败: {}", operation, e);
}`,
  },
  {
    pattern: /ArrayList\s*<.*>\s*\w+\s*=\s*new\s+ArrayList/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '代码规范：使用接口类型声明变量',
    suggestion: '使用 List 接口类型声明变量，便于替换实现类。',
    beforeCode: `ArrayList<User> users = new ArrayList<>();`,
    afterCode: `// 推荐：使用接口类型
List<User> users = new ArrayList<>();

// 如果需要指定初始容量
List<User> users = new ArrayList<>(expectedSize);

// 或使用工具类创建
List<String> names = Arrays.asList("Alice", "Bob");
List<Integer> nums = IntStream.range(1, 100).boxed().collect(Collectors.toList());`,
  },
  {
    pattern: /==\s*(?:true|false)/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '代码规范：布尔值与 true/false 的冗余比较',
    suggestion: '直接使用布尔表达式，使代码更简洁。',
    beforeCode: `if (isValid == true) { ... }
if (hasError == false) { ... }
while (isActive == true) { ... }`,
    afterCode: `if (isValid) { ... }
if (!hasError) { ... }
while (isActive) { ... }`,
  },
  {
    pattern: /new\s+Date\(\)/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '代码规范：使用 Instant 或 LocalDateTime 替代 Date',
    suggestion: 'Java 8+ 推荐使用 Instant、LocalDateTime 等新日期时间 API。',
    beforeCode: `Date now = new Date();
Date date = new Date(timestamp);
SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");`,
    afterCode: `// 使用 Java 8+ 日期时间 API
Instant now = Instant.now();
LocalDateTime dateTime = LocalDateTime.now();
LocalDate date = LocalDate.now();

// 格式化
String formatted = LocalDateTime.now().format(
    DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

// 从时间戳创建
Instant instant = Instant.ofEpochMilli(timestamp);`,
  },
  {
    pattern: /String\s+\w+\s*=\s*new\s+String\(/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '代码规范：不必要的 String 对象创建',
    suggestion: '直接赋值即可，不需要 new String()。',
    beforeCode: `String s1 = new String("hello");
String s2 = new String(bytes);`,
    afterCode: `// 直接赋值
String s1 = "hello";

// 如果需要从字节数组创建
String s2 = new String(bytes, StandardCharsets.UTF_8);
// 或
String s3 = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes)).toString();`,
  },
  {
    pattern: /if\s*\(\s*\w+\s*==\s*null\s*\)/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: '代码规范：非空检查顺序建议',
    suggestion: '建议先处理正常流程，再处理空值，减少嵌套。',
    beforeCode: `if (user != null) {
    if (order != null) {
        if (product != null) {
            // 核心业务逻辑
        }
    }
}`,
    afterCode: `// 卫语句提前返回，减少嵌套
if (user == null) return;
if (order == null) return;
if (product == null) return;

// 核心业务逻辑，正常流程在前面
// ...`,
  },
]

const MYSQL_RULES = [
  {
    pattern: /SELECT\s+\*/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '性能问题：SELECT * 可能导致性能下降',
    suggestion: '明确指定需要的列名，避免不必要的数据传输和索引失效。',
    beforeCode: `SELECT * FROM users WHERE id = 1;
SELECT * FROM orders WHERE status = 'pending';`,
    afterCode: `-- 只查询需要的字段
SELECT id, username, email FROM users WHERE id = 1;

-- 如果需要所有字段，使用索引覆盖
SELECT o.id, o.created_at, o.status, 
       u.name as customer_name
FROM orders o
JOIN users u ON o.user_id = u.id
WHERE o.status = 'pending';`,
  },
  {
    pattern: /FROM\s+\w+\s*,\s*\w+\s*(?:WHERE|ORDER|GROUP|LIMIT|$)/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: 'SQL 规范：使用隐式连接（逗号分隔表）',
    suggestion: '使用显式 JOIN 语法，使查询意图更清晰，区分连接条件和过滤条件。',
    beforeCode: `SELECT * FROM orders, customers 
WHERE orders.customer_id = customers.id;`,
    afterCode: `-- 显式 INNER JOIN
SELECT o.*, c.name as customer_name
FROM orders o
INNER JOIN customers c ON o.customer_id = c.id;

-- 或 LEFT JOIN（根据业务需求）
SELECT o.*, c.name as customer_name
FROM orders o
LEFT JOIN customers c ON o.customer_id = c.id;`,
  },
  {
    pattern: /WHERE.*!=\s*\w+|WHERE.*<>\s*\w+/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '性能问题：不等于查询可能无法使用索引',
    suggestion: '考虑是否可以用其他方式表达逻辑，或确保该列有适当的索引。',
    beforeCode: `SELECT * FROM users WHERE status != 'deleted';
SELECT * FROM orders WHERE type <> 'cancelled';`,
    afterCode: `-- 方案1：使用 IN 或 EXISTS
SELECT * FROM users WHERE status IN ('active', 'pending');

-- 方案2：如果数据分布均匀，考虑索引
CREATE INDEX idx_users_status ON users(status);

-- 方案3：根据业务逻辑重构
SELECT * FROM users 
WHERE COALESCE(status, 'active') = 'active';`,
  },
  {
    pattern: /LIMIT\s+\d+\s*,\s*\d+|\bLIMIT\s+\d+\s+OFFSET\s+\d+/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '性能问题：大偏移量分页导致性能问题',
    suggestion: '使用基于主键的游标分页替代 OFFSET 分页。',
    beforeCode: `-- 传统 OFFSET 分页，越往后越慢
SELECT * FROM orders 
ORDER BY id 
LIMIT 10 OFFSET 100000;`,
    afterCode: `-- 游标分页：利用主键索引，性能稳定
-- 第一页
SELECT * FROM orders 
ORDER BY id 
LIMIT 10;

-- 下一页：记住上一页最后一条的 id
SELECT * FROM orders 
WHERE id > #{last_id}
ORDER BY id 
LIMIT 10;

-- 或使用延迟关联
SELECT o.* FROM orders o
INNER JOIN (SELECT id FROM orders ORDER BY id LIMIT 10 OFFSET 100000) t
ON o.id = t.id;`,
  },
  {
    pattern: /password\s+FROM|passwd\s+FROM|pwd\s+FROM|secret\s+FROM|token\s+FROM/gi,
    severity: 'error' as const,
    category: 'security' as const,
    message: '安全风险：直接查询敏感字段',
    suggestion: '不要在查询中返回敏感字段，密码应使用哈希存储和验证。',
    beforeCode: `SELECT id, username, password FROM users WHERE id = 1;
SELECT * FROM api_keys WHERE key = 'xxx';`,
    afterCode: `-- 用户认证：正确的方式
SELECT id, username FROM users WHERE username = ?;
-- 然后在应用层验证密码哈希
if (BCrypt.checkpw(inputPassword, storedHash)) {
    // 认证成功
}

// API 密钥：使用加密或哈希
SELECT id, key_hint, created_at 
FROM api_keys 
WHERE id = ?;
-- key_hint 只显示前4位如 "sk-****1234"`,
  },
  {
    pattern: /INSERT\s+INTO\s+\w+\s*VALUES\s*\(/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: 'SQL 规范：INSERT 语句未指定列名',
    suggestion: '明确指定插入的列名，便于维护和避免表结构变更导致的问题。',
    beforeCode: `INSERT INTO users VALUES (1, 'Tom', 'tom@example.com');
INSERT INTO orders VALUES (NULL, 1, NOW());`,
    afterCode: `-- 明确指定列名
INSERT INTO users (id, username, email) 
VALUES (1, 'Tom', 'tom@example.com');

-- 批量插入
INSERT INTO users (id, username, email) VALUES
(1, 'Tom', 'tom@example.com'),
(2, 'Jerry', 'jerry@example.com'),
(3, 'Spike', 'spike@example.com');`,
  },
  {
    pattern: /DROP\s+TABLE\s+\w+(?!\s+IF\s+EXISTS)/gi,
    severity: 'warning' as const,
    category: 'norms' as const,
    message: 'SQL 规范：DROP TABLE 未检查表是否存在',
    suggestion: '使用 DROP TABLE IF EXISTS 避免表不存在时出错。',
    beforeCode: `DROP TABLE users;
DROP TABLE orders;`,
    afterCode: `-- 安全删除：先检查再删除
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS orders;

-- 或在事务中执行
START TRANSACTION;
DROP TABLE IF EXISTS temp_data;
COMMIT;`,
  },
  {
    pattern: /SELECT.*COUNT\(\*\).*FROM/gi,
    severity: 'info' as const,
    category: 'performance' as const,
    message: '性能提示：COUNT(*) 全表扫描可能较慢',
    suggestion: '如果频繁需要计数，考虑维护计数器或使用覆盖索引。',
    beforeCode: `SELECT COUNT(*) FROM orders WHERE status = 'pending';
SELECT COUNT(*) FROM users WHERE created_at > '2024-01-01';`,
    afterCode: `-- 方案1：使用覆盖索引加速
SELECT COUNT(*) FROM orders USE INDEX (idx_status)
WHERE status = 'pending';

-- 方案2：维护计数器表（高频访问场景）
-- 订单表有触发器或应用层同步更新 order_count
SELECT order_count FROM stats WHERE type = 'pending_orders';

-- 方案3：近似计数（允许误差的场景）
SELECT TABLE_ROWS FROM information_schema.TABLES
WHERE TABLE_NAME = 'orders';`,
  },
  {
    pattern: /CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS)/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: 'SQL 规范：CREATE TABLE 未使用 IF NOT EXISTS',
    suggestion: '使用 CREATE TABLE IF NOT EXISTS 避免重复创建导致错误。',
    beforeCode: `CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50)
);`,
    afterCode: `-- 幂等创建：先删除再创建或检查存在性
CREATE TABLE IF NOT EXISTS users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(50) NOT NULL COMMENT '用户名',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='用户表';`,
  },
  {
    pattern: /ALTER\s+TABLE\s+\w+\s+ADD\s+COLUMN\s+(?!\s*\w+\s+\w+.*COMMENT)/gi,
    severity: 'info' as const,
    category: 'norms' as const,
    message: 'SQL 规范：ALTER TABLE 添加字段未添加注释',
    suggestion: '为字段添加 COMMENT 注释，便于后续维护。',
    beforeCode: `ALTER TABLE users ADD COLUMN phone VARCHAR(20);`,
    afterCode: `-- 添加字段并注释
ALTER TABLE users 
ADD COLUMN phone VARCHAR(20) 
COMMENT '手机号码'
AFTER email;

-- 完整示例：添加多个字段
ALTER TABLE users
ADD COLUMN phone VARCHAR(20) COMMENT '手机号' AFTER email,
ADD COLUMN real_name VARCHAR(50) COMMENT '真实姓名' AFTER phone,
ADD COLUMN last_login_at DATETIME COMMENT '最后登录时间' AFTER created_at;`,
  },
]

function analyzeCode(code: string, language: 'java' | 'mysql'): Issue[] {
  const rules = language === 'java' ? JAVA_RULES : MYSQL_RULES
  const issues: Issue[] = []
  const lines = code.split('\n')

  rules.forEach((rule) => {
    let lastIndex = 0
    let searchCode = code

    while (true) {
      const match = searchCode.substring(lastIndex).match(rule.pattern)
      if (!match || !match[0]) break

      const matchIndex = searchCode.indexOf(match[0], lastIndex)
      const beforeMatch = searchCode.substring(0, matchIndex)
      let lineNum = (beforeMatch.match(/\n/g) || []).length + 1

      // 获取匹配行的上下文
      const lineStart = code.lastIndexOf('\n', matchIndex - 1) + 1
      const lineEnd = code.indexOf('\n', matchIndex)
      const matchedLine = lineEnd === -1 ? code.substring(lineStart) : code.substring(lineStart, lineEnd)

      if (!issues.some((i) => i.line === lineNum && i.message === rule.message)) {
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
      lastIndex = matchIndex + match[0].length
    }
  })

  // Java 特定检测
  if (language === 'java') {
    lines.forEach((line, index) => {
      if (/Connection\s+\w+\s*=.*\.getConnection\(\)/.test(line)) {
        const afterLines = lines.slice(index + 1).join('\n')
        if (!afterLines.includes('close()') && !afterLines.includes('try-with')) {
          issues.push({
            line: index + 1,
            severity: 'error',
            category: 'performance',
            message: '资源泄漏：Connection 未确保关闭',
            suggestion: '使用 try-with-resources 确保连接关闭。',
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
          })
        }
      }
    })
  }

  return issues.sort((a, b) => a.line - b.line)
}

const server = http.createServer((req, res) => {
  const url = req.url || '/'

  // API route
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
              errors: issues.filter((i) => i.severity === 'error').length,
              warnings: issues.filter((i) => i.severity === 'warning').length,
              suggestions: issues.filter((i) => i.severity === 'info').length,
            },
            timestamp: new Date().toISOString(),
          }))
        }, 600 + Math.random() * 600)
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Internal server error' }))
      }
    })
    return
  }

  // Static files
  let filePath = url === '/' ? '/index.html' : url
  filePath = path.join(ROOT_DIR, filePath)

  const ext = path.extname(filePath)
  const contentTypes: Record<string, string> = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
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
