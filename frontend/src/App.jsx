import { useCallback, useEffect, useState } from 'react'
import './App.css'

const severityForAlert = level => {
  const value = Number(level ?? 0)
  if (value >= 12) return 'critical'
  if (value >= 8) return 'high'
  if (value >= 5) return 'medium'
  return 'low'
}

const formatAlertTime = value => {
  if (!value) return 'Timestamp unavailable'
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? 'Timestamp unavailable'
    : date.toLocaleString()
}

const decisionLabel = investigation => {
  if (!investigation) return 'Not investigated'
  const decision = String(investigation.decision || 'Uncertain')

  return investigation.human_review_required
    ? `${decision} · Human review required`
    : decision
}

const actionLabels = {
  block_ip: 'Block IP',
  disable_account: 'Disable Account',
  isolate_endpoint: 'Isolate Endpoint',
}

const statusLabel = status => {
  const labels = {
    pending: 'Awaiting Approval',
    approved: 'Approved',
    rejected: 'Rejected',
    executed: 'Executed',
  }

  return labels[String(status || '').toLowerCase()] || status || 'Unknown'
}

const riskForAction = action => {
  if (action.action_type === 'block_ip') return 'critical'
  if (action.action_type === 'isolate_endpoint') return 'high'
  return 'medium'
}

function App() {
  const [nav, setNav] = useState('dashboard')
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [reviewer, setReviewer] = useState('')

  const [summary, setSummary] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [investigations, setInvestigations] = useState([])
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState('')

  const loadDashboard = useCallback(async () => {
    setDashboardLoading(true)
    setDashboardError('')

    try {
      const endpoints = [
        '/api/v1/dashboard/summary',
        '/api/v1/alerts?limit=10',
        '/api/v1/investigations?limit=100',
      ]

      const responses = await Promise.all(
        endpoints.map(endpoint => fetch(endpoint))
      )

      const payloads = await Promise.all(
        responses.map(response => response.json().catch(() => ({})))
      )

      const failedIndex = responses.findIndex(response => !response.ok)

      if (failedIndex !== -1) {
        const failed = responses[failedIndex]

        throw new Error(
          payloads[failedIndex].detail ||
          `Dashboard request failed (HTTP ${failed.status})`
        )
      }

      setSummary(payloads[0])
      setAlerts(
        Array.isArray(payloads[1].alerts)
          ? payloads[1].alerts
          : []
      )
      setInvestigations(
        Array.isArray(payloads[2].investigations)
          ? payloads[2].investigations
          : []
      )
    } catch (err) {
      setDashboardError(
        err.message || 'Could not load dashboard data.'
      )
    } finally {
      setDashboardLoading(false)
    }
  }, [])

  const loadActions = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch('/api/v1/response-actions')
      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          data.detail ||
          `Could not load response actions (HTTP ${response.status})`
        )
      }

      setActions(Array.isArray(data.actions) ? data.actions : [])
      setReviewer(data.reviewer || '')
    } catch (err) {
      setError(
        err.message ||
        'Could not connect to the response-actions API.'
      )
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadActions()
    loadDashboard()
  }, [loadActions, loadDashboard])

  const performAction = async (action, operation, body) => {
    setBusyId(action.id)
    setError('')
    setNotice('')

    try {
      const response = await fetch(
        `/api/v1/response-actions/${action.id}/${operation}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          ...(body ? { body: JSON.stringify(body) } : {}),
        }
      )

      const data = await response.json().catch(() => ({}))

      if (!response.ok) {
        throw new Error(
          data.detail || `Action failed (HTTP ${response.status})`
        )
      }

      const messages = {
        approve: 'Action approved. Execution remains a separate step.',
        reject: 'Action rejected and recorded.',
        execute: 'Execution request completed. Check the recorded result.',
      }

      setNotice(messages[operation] || 'Action updated.')
      await loadActions()
    } catch (err) {
      setError(err.message || 'The requested operation failed.')
    } finally {
      setBusyId(null)
    }
  }

  const approve = action => {
    if (!window.confirm(
      `Approve "${actionLabels[action.action_type] || action.action_type}: ${action.target}"?`
    )) {
      return
    }

    performAction(action, 'approve')
  }

  const deny = action => {
    const reason = window.prompt(
      'Why are you rejecting this action?\nMinimum 3 characters.'
    )

    if (reason === null) return

    if (reason.trim().length < 3) {
      setError(
        'Please provide a rejection reason of at least 3 characters.'
      )
      return
    }

    performAction(action, 'reject', { reason: reason.trim() })
  }

  const execute = action => {
    if (!window.confirm(
      `Request simulated execution of "${actionLabels[action.action_type] || action.action_type}: ${action.target}"?\n\nThis prototype is designed to simulate actions, not make real system changes.`
    )) {
      return
    }

    performAction(action, 'execute')
  }

  const pendingCount = actions.filter(
    action => String(action.status).toLowerCase() === 'pending'
  ).length

  const stats = [
    {
      label: 'Total Alerts',
      value: summary ? String(summary.total_alerts ?? 0) : '—',
      delta: dashboardLoading ? 'Loading' : 'PostgreSQL',
      color: 'red',
      icon: '⚠',
    },
    {
      label: 'Critical Alerts',
      value: summary ? String(summary.critical_alerts ?? 0) : '—',
      delta: 'Wazuh level ≥ 12',
      color: 'green',
      icon: '🛡',
    },
    {
      label: 'Pending Review',
      value: summary ? String(summary.pending_review ?? 0) : '—',
      delta: dashboardLoading ? 'Loading' : 'Investigations',
      color: 'orange',
      icon: '⏳',
    },
    {
      label: 'Investigations',
      value: summary
        ? String(summary.total_investigations ?? 0)
        : '—',
      delta: dashboardLoading ? 'Loading' : 'PostgreSQL',
      color: 'cyan',
      icon: '⚡',
    },
  ]

  // These activity metrics are calculated from the investigation
  // records returned by the dashboard API, not fabricated events.
  const timeline = [
    {
      label: 'Investigations loaded',
      value: investigations.length,
      type: 'scan',
    },
    {
      label: 'Require human review',
      value: investigations.filter(
        item => item.human_review_required
      ).length,
      type: 'escalate',
    },
    {
      label: 'True positive decisions',
      value: investigations.filter(
        item => item.decision === 'True Positive'
      ).length,
      type: 'correlate',
    },
    {
      label: 'False positive decisions',
      value: investigations.filter(
        item => item.decision === 'False Positive'
      ).length,
      type: 'resolve',
    },
    {
      label: 'Linked to incidents',
      value: investigations.filter(
        item => item.incident_id != null
      ).length,
      type: 'update',
    },
  ]

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: '▣' },
    { id: 'alerts', label: 'Alerts', icon: '🔔' },
    { id: 'agents', label: 'Agents', icon: '⬡' },
    { id: 'playbooks', label: 'Playbooks', icon: '☰' },
    { id: 'reports', label: 'Reports', icon: '◩' },
    { id: 'settings', label: 'Settings', icon: '⚙' },
  ]

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">◆</span>
          <span className="brand-text">
            SOC<strong>Agent</strong>
          </span>
        </div>

        <nav className="nav">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-btn${nav === item.id ? ' active' : ''}`}
              onClick={() => setNav(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <span className="dot online" />
          Agent Online
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <h2 className="page-title">Security Dashboard</h2>
            <p className="page-sub">
              Autonomous SOC · Human-Gated
            </p>
          </div>

          <span className="live">
            <span className="pulse" /> LIVE
          </span>
        </header>

        {error && (
          <div
            role="alert"
            className="card"
            style={{ marginBottom: 16 }}
          >
            <strong>API error:</strong> {error}
            <button
              className="btn"
              onClick={loadActions}
              style={{ marginLeft: 12 }}
            >
              Retry
            </button>
          </div>
        )}

        {notice && (
          <div
            role="status"
            className="card"
            style={{ marginBottom: 16 }}
          >
            {notice}
            <button
              className="btn"
              onClick={() => setNotice('')}
              style={{ marginLeft: 12 }}
            >
              Dismiss
            </button>
          </div>
        )}

        <section className="stats">
          {stats.map(stat => (
            <article
              key={stat.label}
              className={`stat-card c-${stat.color}`}
            >
              <span className="stat-icon">{stat.icon}</span>

              <div className="stat-body">
                <span className="stat-val">{stat.value}</span>
                <span className="stat-lbl">{stat.label}</span>
              </div>

              <span className="stat-delta">{stat.delta}</span>
            </article>
          ))}
        </section>

        <div className="grid">
          <section className="card gate">
            <div className="card-head">
              <h3>Human Gate — Awaiting Approval</h3>
              <span className="pill">{pendingCount}</span>
            </div>

            {reviewer && (
              <p className="gate-agent">
                Authenticated reviewer: {reviewer}
              </p>
            )}

            <button
              className="btn"
              onClick={loadActions}
              disabled={loading || busyId !== null}
              style={{ marginBottom: 12 }}
            >
              {loading ? 'Refreshing…' : '↻ Refresh Actions'}
            </button>

            {loading && actions.length === 0 && (
              <p>Loading persisted response actions…</p>
            )}

            {!loading && actions.length === 0 && !error && (
              <p>
                No response actions are currently recorded by the backend.
              </p>
            )}

            {actions.map(action => {
              const status = String(action.status || '').toLowerCase()
              const risk = riskForAction(action)
              const isBusy = busyId === action.id

              return (
                <div
                  key={action.id}
                  className={`gate-row ${risk}`}
                >
                  <div className="gate-info">
                    <span className={`risk ${risk}`}>{risk}</span>

                    <span className="gate-act">
                      {actionLabels[action.action_type] ||
                        action.action_type}{' '}
                      {action.target}
                    </span>

                    <span className="gate-agent">
                      Incident #{action.incident_id} ·{' '}
                      {statusLabel(action.status)}
                    </span>

                    {action.result && (
                      <span className="gate-agent">
                        {action.result}
                      </span>
                    )}

                    {action.rejection_reason && (
                      <span className="gate-agent">
                        Rejection reason: {action.rejection_reason}
                      </span>
                    )}
                  </div>

                  {isBusy ? (
                    <span className="tag">Processing…</span>
                  ) : status === 'pending' ? (
                    <div className="gate-btns">
                      <button
                        className="btn ok"
                        onClick={() => approve(action)}
                      >
                        ✓ Approve
                      </button>

                      <button
                        className="btn no"
                        onClick={() => deny(action)}
                      >
                        ✕ Reject
                      </button>
                    </div>
                  ) : status === 'approved' ? (
                    <div className="gate-btns">
                      <span className="tag approved">
                        ✓ Approved
                      </span>

                      <button
                        className="btn ok"
                        onClick={() => execute(action)}
                      >
                        Run Simulation
                      </button>
                    </div>
                  ) : (
                    <span className={`tag ${status}`}>
                      {statusLabel(action.status)}
                    </span>
                  )}
                </div>
              )
            })}
          </section>

          <section className="card feed">
            <div className="card-head">
              <h3>🚨 Alert Feed · PostgreSQL</h3>
              <span className="pill">{alerts.length}</span>
            </div>

            {dashboardLoading && alerts.length === 0 && (
              <p>Loading persisted alerts…</p>
            )}

            {!dashboardLoading && dashboardError && (
              <p role="alert">
                Could not load live alerts: {dashboardError}
              </p>
            )}

            {!dashboardLoading &&
              !dashboardError &&
              alerts.length === 0 && (
                <p>No alerts are currently stored in the database.</p>
              )}

            {alerts.map(alert => {
              const investigation = investigations.find(
                item =>
                  Number(item.alert_database_id) === Number(alert.id)
              )

              const severity = severityForAlert(alert.rule_level)
              const source =
                alert.source_ip ||
                alert.agent_name ||
                alert.username ||
                'Source unavailable'

              return (
                <div
                  key={alert.id}
                  className={`alert-row ${severity}`}
                >
                  <span className={`sev-dot ${severity}`} />

                  <div className="alert-info">
                    <span className="alert-title">
                      {alert.rule_description ||
                        `Wazuh alert ${alert.wazuh_alert_id || alert.id}`}
                    </span>

                    <span className="alert-meta">
                      {source} · Rule level {alert.rule_level ?? 'N/A'} ·{' '}
                      {formatAlertTime(alert.timestamp)}
                    </span>

                    <span className="alert-meta">
                      Investigation: {decisionLabel(investigation)}
                      {investigation?.severity
                        ? ` · AI severity: ${investigation.severity}`
                        : ''}
                    </span>

                    {alert.wazuh_alert_id?.startsWith('VALIDATOR-') && (
                      <span className="alert-meta">
                        Synthetic validation event
                      </span>
                    )}
                  </div>

                  <span
                    className={`tag ${
                      investigation?.decision === 'True Positive'
                        ? 'escalated'
                        : investigation?.decision === 'False Positive'
                          ? 'resolved'
                          : 'pending'
                    }`}
                  >
                    {investigation?.decision || 'Not investigated'}
                  </span>
                </div>
              )
            })}
          </section>

          <section className="card tline">
            <div className="card-head">
              <h3>🤖 Investigation Activity · Live Data</h3>
            </div>

            {dashboardLoading && (
              <p>Loading investigation activity…</p>
            )}

            {!dashboardLoading && dashboardError && (
              <p role="alert">
                Could not load investigation activity: {dashboardError}
              </p>
            )}

            {!dashboardLoading &&
              !dashboardError &&
              timeline.map(item => (
                <div
                  key={item.label}
                  className={`tl-row ${item.type}`}
                >
                  <span className="tl-time">LIVE</span>
                  <span className="tl-dot" />

                  <span className="tl-event">
                    {item.label}: <strong>{item.value}</strong>
                  </span>
                </div>
              ))}

            {!dashboardLoading && !dashboardError && (
              <p className="alert-meta">
                Counts reflect the investigation records loaded by the
                dashboard, not a chronological activity log.
              </p>
            )}
          </section>
        </div>
      </main>
    </div>
  )
}

export default App
