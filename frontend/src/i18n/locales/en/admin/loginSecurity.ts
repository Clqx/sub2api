export default {
  loginSecurity: {
    title: 'Login Verification IPs',
    description: 'Review login challenge failures and automatic blocks. Client IPs are temporarily blocked when the configured threshold is reached.',
    empty: 'No login verification IP records',
    loadFailed: 'Failed to load login verification IP records',
    filters: {
      keyword: 'IP / User-Agent',
      keywordPlaceholder: 'Search client IP or User-Agent',
      status: 'Status',
      all: 'All'
    },
    status: {
      blocked: 'Blocked',
      monitoring: 'Monitoring',
      cleared: 'Cleared'
    },
    columns: {
      ip: 'Client IP',
      status: 'Status',
      failures: 'Current / Total Failures',
      blocks: 'Blocks',
      lastFailed: 'Last Failure',
      blockedUntil: 'Blocked Until',
      userAgent: 'Latest User-Agent'
    },
    unblock: 'Unblock',
    unblockConfirm: {
      title: 'Unblock IP',
      message: 'Remove the login challenge block for {ip}? Failure and block history will be retained.',
      success: 'Unblocked {ip}',
      failed: 'Failed to unblock IP'
    }
  }
}
