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
  category: string
  message: string
  suggestion: string
  beforeCode?: string
  afterCode?: string
}

// ========== 阿里JAVA编码规范检测规则 ==========

// 一、命名风格
const NAMING_RULES = [
  // 【强制】变量、方法命名不能以_或$开头结尾
  {
    pattern: /\b[_\$]+\w+|\w+[_\$]+\b/g,
    severity: 'error',
    message: '命名风格：变量名不能以_或$开头或结尾',
    suggestion: '遵循阿里规范：命名不能以下划线或美元符号开头或结尾',
    beforeCode: `int _count = 0; String name$ = "test";`,
    afterCode: `int count = 0; String name = "test";`,
  },
  // 【强制】POJO类中布尔类型变量不要加is前缀
  {
    pattern: /\bboolean\s+is[A-Z]\w*\s*[=;]/g,
    severity: 'warning',
    message: '命名风格：POJO类中布尔类型变量不要加is前缀',
    suggestion: '数据库字段表示is_deleted，对应属性应该叫deleted',
    beforeCode: `private boolean isDeleted; // BOOLEAN IS_DELETED`,
    afterCode: `private boolean deleted; // 属性名为 deleted`,
  },
  // 【推荐】方法命名使用驼峰，常量使用全大写+下划线
  {
    pattern: /\bstatic\s+final\s+[a-z][a-zA-Z0-9]*\s*=/g,
    severity: 'warning',
    message: '命名风格：常量命名应使用全大写+下划线',
    suggestion: 'static final常量应命名为MAX_COUNT而非maxCount',
    beforeCode: `static final int maxCount = 100;`,
    afterCode: `static final int MAX_COUNT = 100;`,
  },
]

// 二、OOP规约
const OOP_RULES = [
  // 【强制】Object的equals方法容易抛NPE，应使用常量或确定对象来调用equals
  {
    pattern: /\.equals\(\s*["'\w]+\s*\)/g,
    severity: 'error',
    message: 'OOP规约：Object.equals(null)易抛出NPE',
    suggestion: '使用 Objects.equals(a, b) 或 "constant".equals(obj)',
    beforeCode: `obj.equals("test"); // obj为null时会NPE`,
    afterCode: `"test".equals(obj); // 或 Objects.equals(obj, "test")`,
  },
  // 【强制】所有POJO类属性必须使用包装类型
  {
    pattern: /\bprivate\s+(int|long|double|float|boolean)\s+\w+\s*;/g,
    severity: 'error',
    message: 'OOP规约：POJO类属性不能使用基本类型',
    suggestion: 'POJO类属性必须使用包装类型，如Integer而非int',
    beforeCode: `private int age; // 基本类型无法表示null`,
    afterCode: `private Integer age; // 包装类型可表示null`,
  },
  // 【推荐】使用索引访问Set元素，Set无序
  {
    pattern: /set\.toArray\(\)\[\s*\w+\s*\]|set\.get\(/gi,
    severity: 'warning',
    message: 'OOP规约：Set集合不能使用索引访问',
    suggestion: 'Set是无序集合，不能通过索引访问，应使用迭代器或forEach',
    beforeCode: `set.toArray()[0] // 不安全，顺序不确定`,
    afterCode: `Iterator it = set.iterator(); it.next();`,
  },
]

// 三、集合处理
const COLLECTION_RULES = [
  // 【强制】ArrayList的subList结果不能强转成ArrayList
  {
    pattern: /\(ArrayList\)\s*\w+\.subList\(/gi,
    severity: 'error',
    message: '集合处理：subList结果不能强转为ArrayList',
    suggestion: 'subList返回的是视图，强转会失败',
    beforeCode: `ArrayList list = (ArrayList) subList; // 错误`,
    afterCode: `List sub = list.subList(0, 10); // 使用List接收`,
  },
  // 【强制】使用集合转数组必须使用toArray(T[] array)
  {
    pattern: /\b\.toArray\(\)\s*(?!\()/gi,
    severity: 'warning',
    message: '集合处理：集合转数组应使用toArray(T[])',
    suggestion: '无参toArray返回Object[]，可能引发类型转换异常',
    beforeCode: `Integer[] arr = list.toArray(); // 可能有ClassCastException`,
    afterCode: `Integer[] arr = list.toArray(new Integer[0]);`,
  },
  // 【强制】使用entrySet遍历Map
  {
    pattern: /for\s*\(\s*\(\s*\w+\s+\w+\s*:\s*\w+\.keySet\(\)\s*\)/gi,
    severity: 'warning',
    message: '集合处理：遍历Map应使用entrySet',
    suggestion: '同时需要key和value时，用entrySet替代keySet效率更高',
    beforeCode: `for (String key : map.keySet()) { map.get(key); }`,
    afterCode: `for (Map.Entry<String, String> entry : map.entrySet()) { entry.getKey(); entry.getValue(); }`,
  },
]

// 四、控制语句
const CONTROL_RULES = [
  // 【强制】switch语句必须有default
  {
    pattern: /switch\s*\([^)]+\)\s*\{[^}]*\bcase\b[^}]*(?:\{[^}]*\})?[^}]*\}/gi,
    severity: 'warning',
    message: '控制语句：switch语句建议有default分支',
    suggestion: '即使不需要default，也建议保留以处理未知情况',
    beforeCode: `switch (status) { case 1: break; } // 无default`,
    afterCode: `switch (status) { case 1: break; default: break; }`,
  },
  // 【强制】在if/else/for/while/do语句中必须使用大括号
  {
    pattern: /\b(if|else|for|while)\s*\([^)]+\)\s*[^{]/gi,
    severity: 'error',
    message: '控制语句：if/else/for/while必须使用大括号',
    suggestion: '阿里规范强制：即使只有一行代码也必须使用大括号',
    beforeCode: `if (valid) doSomething(); // 禁止`,
    afterCode: `if (valid) { doSomething(); }`,
  },
]

// 五、并发处理
const CONCURRENCY_RULES = [
  // 【强制】SimpleDateFormat线程不安全
  {
    pattern: /\bSimpleDateFormat\s+\w+\s*=/g,
    severity: 'error',
    message: '并发处理：SimpleDateFormat线程不安全',
    suggestion: '使用ThreadLocal或Java8的DateTimeFormatter',
    beforeCode: `SimpleDateFormat sdf = new SimpleDateFormat(); // 线程不安全`,
    afterCode: `private static ThreadLocal<DateFormat> df = ThreadLocal.withInitial(() -> new SimpleDateFormat());`,
  },
  // 【强制】volatile不能保证原子性
  {
    pattern: /\bvolatile\s+\b(int|long)\b\s+\w+\s*[;=(]/g,
    severity: 'error',
    message: '并发处理：volatile不能保证非long/double变量的原子性',
    suggestion: 'long/double型变量使用volatile不能保证原子性，需用AtomicLong',
    beforeCode: `volatile long count; // 不能保证原子性`,
    afterCode: `private AtomicLong count = new AtomicLong();`,
  },
]

// 六、异常处理
const EXCEPTION_RULES = [
  // 【强制】finally块必须对资源对象进行关闭
  {
    pattern: /close\s*\(\s*\)\s*;(?!\s*})\s*$/gim,
    severity: 'error',
    message: '异常处理：finally块中必须关闭资源',
    suggestion: '使用try-with-resources或finally中确保关闭',
    beforeCode: `conn.close(); // 可能不执行`,
    afterCode: `try (Connection conn = ...) { } // 自动关闭`,
  },
  // 【强制】捕获异常后要处理，不要生吞
  {
    pattern: /catch\s*\([^)]+\)\s*\{\s*\}/gi,
    severity: 'warning',
    message: '异常处理：不能生吞异常',
    suggestion: '至少记录日志或重新抛出',
    beforeCode: `catch (Exception e) { } // 生吞异常`,
    afterCode: `catch (Exception e) { log.error("", e); throw e; }`,
  },
  // 【强制】捕获已知异常时不要使用Exception
  {
    pattern: /catch\s*\(\s*Exception\s+\w+\s*\)/gi,
    severity: 'info',
    message: '异常处理：捕获异常应使用具体类型',
    suggestion: '不要直接catch(Exception)，应catch具体异常类型',
    beforeCode: `catch (Exception e) { }`,
    afterCode: `catch (IOException e) { }`,
  },
]

// 七、运行时异常检测
const RUNTIME_RULES = [
  // 除零检测
  {
    pattern: /\/\s*0(?:\s*;|\s*\)|\s*,)/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：除零错误 ArithmeticException',
    suggestion: '除法运算前必须检查除数是否为零',
    beforeCode: `int result = a / 0; // 除零`,
    afterCode: `if (b != 0) { result = a / b; }`,
  },
  // null直接使用
  {
    pattern: /new\s+StringBuilder\s*\(\s*\)\s*;\s*sb\.|new\s+ArrayList\s*\(\s*\)\s*;\s*list\.|new\s+HashMap\s*\(\s*\)\s*;\s*map\./gi,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：变量声明为null后直接使用',
    suggestion: '声明后立即初始化，或使用前判空',
    beforeCode: `StringBuilder sb = null; sb.append("x");`,
    afterCode: `StringBuilder sb = new StringBuilder(); sb.append("x");`,
  },
  // NPE风险：直接调用可能为null的对象方法
  {
    pattern: /\w+\.getString\(|\w+\.getInt\(|\w+\.trim\(\)|\(\w+\)\s*\.\w+\(/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：对象可能为null导致NPE',
    suggestion: '方法调用前进行null检查，或使用Optional',
    beforeCode: `obj.method(); // obj可能为null`,
    afterCode: `if (obj != null) { obj.method(); }`,
  },
  // 集合操作前判空
  {
    pattern: /\w+\.size\(\)\s*[><=]|\w+\.isEmpty\(\)|\w+\[\s*0\s*\]/g,
    severity: 'warning',
    category: 'runtime',
    message: '运行时异常：集合操作前建议判空',
    suggestion: '调用size()或访问元素前先检查集合是否为空',
    beforeCode: `if (list.size() > 0) { } // 先size再判空`,
    afterCode: `if (!list.isEmpty()) { } // isEmpty更简洁高效`,
  },
]

// 八、安全相关
const SECURITY_RULES = [
  // SQL注入：检测 "SQL... + 变量 或 "SQL" + 变量
  {
    pattern: /("\s*(?:SELECT|INSERT|UPDATE|DELETE).*\+)|(\+\s*\w+\s*;\s*$)/gm,
    severity: 'error',
    category: 'security',
    message: '安全风险：SQL注入风险，字符串拼接SQL',
    suggestion: '使用PreparedStatement参数化查询',
    beforeCode: `"SELECT * FROM users WHERE id=" + userId`,
    afterCode: `"SELECT * FROM users WHERE id=?"`,
  },
  // 硬编码密码
  {
    pattern: /password\s*=\s*["'][^"']+["']|pwd\s*=\s*["'][^"']+["']/gi,
    severity: 'error',
    category: 'security',
    message: '安全风险：禁止硬编码密码',
    suggestion: '密码应通过配置文件或环境变量获取',
    beforeCode: `password = "123456";`,
    afterCode: `password = System.getenv("DB_PASSWORD");`,
  },
  // 明文传输密码
  {
    pattern: /password\s*\.\s*getBytes\(|new\s+String\s*\(\s*password\s*\)/gi,
    severity: 'warning',
    category: 'security',
    message: '安全风险：密码明文处理',
    suggestion: '密码应加密存储和传输，使用哈希+盐值',
    beforeCode: `String pwd = new String(password);`,
    afterCode: `String pwd = Base64.encode(password); // 加密传输`,
  },
]

// 九、MySQL规范
const MYSQL_RULES = [
  // SELECT *
  {
    pattern: /SELECT\s+\*/gi,
    severity: 'warning',
    category: 'performance',
    message: 'MySQL规范：避免使用SELECT *',
    suggestion: '只查询需要的字段，减少网络传输和内存消耗',
    beforeCode: `SELECT * FROM users`,
    afterCode: `SELECT id, name, email FROM users`,
  },
  // 隐式连接
  {
    pattern: /FROM\s+\w+\s*,\s*\w+/gi,
    severity: 'error',
    category: 'security',
    message: 'MySQL规范：禁止使用隐式连接（逗号分隔表）',
    suggestion: '使用显式JOIN ON语法',
    beforeCode: `FROM orders, customers WHERE ...`,
    afterCode: `FROM orders o JOIN customers c ON o.customer_id = c.id`,
  },
  // 密码字段
  {
    pattern: /password/i,
    severity: 'warning',
    category: 'security',
    message: 'MySQL规范：禁止SELECT密码字段',
    suggestion: '密码应加密存储，查询时不要返回密码明文',
    beforeCode: `SELECT password FROM users`,
    afterCode: `-- 不要返回password字段`,
  },
  // 避免OR
  {
    pattern: /\bOR\b.+\bIN\b|\bOR\b.+\s*=\s*/gi,
    severity: 'info',
    category: 'performance',
    message: 'MySQL规范：IN查询数据量过大会影响性能',
    suggestion: 'IN中数据量建议不超过500个',
    beforeCode: `WHERE id IN (1,2,3,...,1000)`,
    afterCode: `WHERE id IN (1,2,3,...500) OR 使用批量查询`,
  },
]

// ========== 核心检测逻辑 ==========

// 1. 检测 null 变量直接使用
function checkNullUsage(code: string): Issue[] {
  const issues: Issue[] = []
  const lines = code.split('\n')
  const nullVars = new Map<string, { line: number, type: string }>()
  
  // 收集 null 声明
  lines.forEach((line, idx) => {
    const match = line.match(/\b(String|StringBuilder|List|Map|Set|Object|Integer|Long|Double|Byte|Connection|Statement|ResultSet|\w+)\s+(\w+)\s*=\s*null\s*;/)
    if (match) {
      nullVars.set(match[2], { line: idx + 1, type: match[1] })
    }
  })
  
  // 检测 null 变量的直接使用
  lines.forEach((line, idx) => {
    for (const [varName, info] of nullVars) {
      // 匹配 "变量." 或 "变量(" 但排除 "变量 = "
      if (line.includes(varName + '.') || (line.includes(varName + '(') && !line.match(new RegExp(`${varName}\\s*=\\s*null`)))) {
        issues.push({
          line: idx + 1,
          severity: 'error',
          category: 'runtime',
          message: `运行时异常：变量"${varName}"声明为null后直接使用`,
          suggestion: `在方法调用前初始化：${info.type} ${varName} = new ${info.type}();`,
          beforeCode: `${info.type} ${varName} = null;\n${line.trim()}`,
          afterCode: `${info.type} ${varName} = new ${info.type}();`,
        })
        break
      }
    }
  })
  
  return issues
}

// 2. 主分析函数
function analyzeCode(code: string, language: string): Issue[] {
  const issues: Issue[] = []
  const lines = code.split('\n')
  const seen = new Set<string>()

  if (language === 'java') {
    // 运行时异常检测
    for (const rule of RUNTIME_RULES) {
      lines.forEach((line, idx) => {
        if (rule.pattern.test(line)) {
          const key = `runtime:${idx}:${rule.message}`
          if (!seen.has(key)) {
            seen.add(key)
            issues.push({
              line: idx + 1,
              severity: rule.severity,
              category: rule.category || 'runtime',
              message: rule.message,
              suggestion: rule.suggestion,
              beforeCode: rule.beforeCode,
              afterCode: rule.afterCode,
            })
          }
          rule.pattern.lastIndex = 0
        }
      })
    }

    // null使用检测
    issues.push(...checkNullUsage(code))

    // 其他规则
    const allRules = [
      ...NAMING_RULES,
      ...OOP_RULES,
      ...COLLECTION_RULES,
      ...CONTROL_RULES,
      ...CONCURRENCY_RULES,
      ...EXCEPTION_RULES,
      ...SECURITY_RULES,
    ]

    for (const rule of allRules) {
      lines.forEach((line, idx) => {
        if (rule.pattern.test(line)) {
          const key = `${rule.category || 'other'}:${idx}:${rule.message}`
          if (!seen.has(key)) {
            seen.add(key)
            issues.push({
              line: idx + 1,
              severity: rule.severity,
              category: rule.category || 'norms',
              message: rule.message,
              suggestion: rule.suggestion,
              beforeCode: rule.beforeCode,
              afterCode: rule.afterCode,
            })
          }
          rule.pattern.lastIndex = 0
        }
      })
    }
  } else if (language === 'mysql') {
    for (const rule of MYSQL_RULES) {
      lines.forEach((line, idx) => {
        if (rule.pattern.test(line)) {
          const key = `mysql:${idx}:${rule.message}`
          if (!seen.has(key)) {
            seen.add(key)
            issues.push({
              line: idx + 1,
              severity: rule.severity,
              category: rule.category || 'norms',
              message: rule.message,
              suggestion: rule.suggestion,
              beforeCode: rule.beforeCode,
              afterCode: rule.afterCode,
            })
          }
          rule.pattern.lastIndex = 0
        }
      })
    }
  }

  return issues
}

// ========== HTTP服务器 ==========

function handleRequest(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`)

  if (url.pathname === '/api/code-review' && req.method === 'POST') {
    let body = ''
    req.on('data', chunk => body += chunk)
    req.on('end', () => {
      try {
        const { code, language } = JSON.parse(body)
        const issues = analyzeCode(code, language || 'java')
        const summary = {
          total: issues.length,
          errors: issues.filter(i => i.severity === 'error').length,
          warnings: issues.filter(i => i.severity === 'warning').length,
          suggestions: issues.filter(i => i.severity === 'info').length,
        }
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ issues, summary, timestamp: new Date().toISOString() }))
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Invalid request' }))
      }
    })
    return
  }

  let filePath = url.pathname === '/' ? '/index.html' : url.pathname
  filePath = path.join(ROOT_DIR, filePath)

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404)
      res.end('Not found')
      return
    }
    const ext = path.extname(filePath)
    const contentType = ext === '.css' ? 'text/css' : ext === '.js' ? 'application/javascript' : 'text/html'
    res.writeHead(200, { 'Content-Type': contentType })
    res.end(data)
  })
}

http.createServer(handleRequest).listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
