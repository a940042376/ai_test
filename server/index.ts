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

// 精简规则 - 避免重复
const JAVA_RULES: any[] = [
  // SQL注入
  {
    pattern: /SELECT\s+\*\s+FROM.*WHERE.*\+|executeQuery\(.*\+|prepareStatement\(.*\+/gi,
    severity: 'error',
    category: 'security',
    message: 'SQL 注入风险：字符串拼接方式构建 SQL',
    suggestion: '使用 PreparedStatement 参数化查询',
    beforeCode: `String query = "SELECT * FROM users WHERE id = " + id;`,
    afterCode: `String sql = "SELECT * FROM users WHERE id = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setLong(1, id);`,
  },
  // 除零
  {
    pattern: /\/\s*0\s*;|\/\s*\$\{|[\d\.\w]+\s*\/\s*\(.*0.*\)/g,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：除零错误',
    suggestion: '除法前检查除数是否为零',
    beforeCode: `int result = a / 0;`,
    afterCode: `if (b != 0) { result = a / b; }`,
  },
  // 变量命名大写开头
  {
    pattern: /\b(int|long|double|float|String)\s+[A-Z][A-Za-z0-9]*\s*=/g,
    severity: 'error',
    category: 'norms',
    message: '命名规范：变量名不能以大写开头',
    suggestion: '使用小写字母开头（camelCase）',
    beforeCode: `int Number = 10;`,
    afterCode: `int number = 10;`,
  },
  // 空指针风险
  {
    pattern: /new\s+\w+\(rs\.getString\(/gi,
    severity: 'error',
    category: 'runtime',
    message: '运行时异常：空指针风险',
    suggestion: 'ResultSet.getString() 可能返回 null',
    beforeCode: `User user = new User(rs.getString("name"));`,
    afterCode: `String name = rs.getString("name");
if (name != null) { user.setName(name); }`,
  },
  // System.out
  {
    pattern: /System\.out\.print/gi,
    severity: 'info',
    category: 'norms',
    message: '代码规范：避免使用 System.out',
    suggestion: '使用日志框架（SLF4J）',
    beforeCode: `System.out.println("debug");`,
    afterCode: `log.info("debug");`,
  },
  // 空catch块
  {
    pattern: /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}/gi,
    severity: 'warning',
    category: 'best-practice',
    message: '代码规范：捕获空异常块',
    suggestion: '至少记录异常日志',
    beforeCode: `catch (Exception e) { }`,
    afterCode: `catch (Exception e) { log.error("", e); }`,
  },
]

const MYSQL_RULES: any[] = [
  // SELECT *
  {
    pattern: /SELECT\s+\*/gi,
    severity: 'warning',
    category: 'performance',
    message: '性能问题：避免使用 SELECT *',
    suggestion: '只查询需要的字段',
    beforeCode: `SELECT * FROM users`,
    afterCode: `SELECT id, name, email FROM users`,
  },
  // 隐式连接
  {
    pattern: /FROM\s+\w+\s*,\s*\w+/gi,
    severity: 'error',
    category: 'security',
    message: '安全风险：隐式连接（逗号分隔表）',
    suggestion: '使用显式 JOIN',
    beforeCode: `SELECT * FROM orders, customers`,
    afterCode: `SELECT * FROM orders o JOIN customers c ON o.customer_id = c.id`,
  },
  // 密码字段
  {
    pattern: /password/i,
    severity: 'warning',
    category: 'security',
    message: '安全建议：密码字段应加密存储',
    suggestion: '使用哈希存储，不要明文',
    beforeCode: `SELECT password FROM users`,
    afterCode: `SELECT * FROM users (不要返回密码)`,
  },
]

// 变量声明为null后直接使用（无判空）
function checkNullUsage(code: string): Issue[] {
  const issues: Issue[] = []
  const lines = code.split('\n')
  
  // 匹配 "类型 变量 = null;" 的声明
  const nullDecl = /\b(String|StringBuilder|List|Map|Set|Object|\w+)\s+(\w+)\s*=\s*null\s*;/g
  // 匹配 "变量." 模式（后续使用）
  const usage = /\b(\w+)\.\w+/g
  
  for (const line of lines) {
    nullDecl.lastIndex = 0
    const declMatch = nullDecl.exec(line)
    if (declMatch) {
      const varName = declMatch[2]
      usage.lastIndex = 0
      // 在后续行中查找该变量的使用
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(varName + '.')) {
          issues.push({
            line: i + 1,
            severity: 'error',
            category: 'runtime',
            message: '运行时异常：变量声明为 null 后直接使用',
            suggestion: `变量 ${varName} 声明为 null，调用 ${varName}.xxx 会导致 NPE`,
            beforeCode: `${varName} = null;`,
            afterCode: `${varName} = new ${declMatch[1]}();`,
          })
          break
        }
      }
    }
  }
  return issues
}

function analyzeCode(code: string, language: string): Issue[] {
  const issues: Issue[] = []
  const lines = code.split('\n')

  if (language === 'java') {
    issues.push(...checkNullUsage(code))
  }

  const rules = language === 'java' ? JAVA_RULES : MYSQL_RULES

  lines.forEach((line, lineIndex) => {
    for (const rule of rules) {
      if (rule.pattern.test(line)) {
        const key = `${rule.severity}:${rule.message}`
        if (!seen.has(key)) {
          seen.add(key)
          issues.push({
            line: lineIndex + 1,
            severity: rule.severity,
            category: rule.category,
            message: rule.message,
            suggestion: rule.suggestion,
            beforeCode: rule.beforeCode,
            afterCode: rule.afterCode,
          })
        }
        rule.pattern.lastIndex = 0
      }
    }
  })

  return issues
}

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
