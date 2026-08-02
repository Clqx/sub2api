export default {
  loginSecurity: {
    title: '登录验证 IP',
    description: '查看登录验证码失败与自动封禁记录。达到服务端配置阈值后，客户端 IP 将被临时封禁。',
    empty: '暂无登录验证码 IP 记录',
    loadFailed: '加载登录验证 IP 记录失败',
    filters: {
      keyword: 'IP / User-Agent',
      keywordPlaceholder: '搜索客户端 IP 或 User-Agent',
      status: '状态',
      all: '全部'
    },
    status: {
      blocked: '已封禁',
      monitoring: '观察中',
      cleared: '已解除'
    },
    columns: {
      ip: '客户端 IP',
      status: '状态',
      failures: '当前 / 累计失败',
      blocks: '封禁次数',
      lastFailed: '最近失败',
      blockedUntil: '封禁截止',
      userAgent: '最近 User-Agent'
    },
    unblock: '解除封禁',
    unblockConfirm: {
      title: '解除 IP 封禁',
      message: '解除 {ip} 的登录验证码封禁？历史失败与封禁次数仍会保留。',
      success: '已解除 {ip} 的封禁',
      failed: '解除封禁失败'
    }
  }
}
