import { useCallback, useEffect, useRef, useState } from 'react'
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

const displayValue = value => {
  if (value === null || value === undefined || value === '') return '—'
  return String(value)
}

function App() {
  const dashboardRequestInFlight = useRef(false)
  const [nav, setNav] = useState('dashboard')
  const [actions, setActions] = useState([])
  const [loading, setLoading] = useState(true)
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [reviewer, setReviewer] = useState('')

  const [summary, setSummary] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [investigations, setInvestigations] = useState([])
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState('')
  const [manualTickets, setManualTickets] = useState([])
  const [localEscalations, setLocalEscalations] = useState([])
  const [escalationTarget, setEscalationTarget] = useState(null)
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [localReviews, setLocalReviews] = useState({})
  const [reportStartDate, setReportStartDate] = useState(
    `${new Date().getFullYear()}-01-01`
  )
  const [reportEndDate, setReportEndDate] = useState(
    new Date().toISOString().slice(0, 10)
  )
  const [reportUseCase, setReportUseCase] = useState('All')

  const [ruleSubmissions, setRuleSubmissions] = useState([])
  const [ruleCategoryFilter, setRuleCategoryFilter] = useState('All')
  const [ruleSearch, setRuleSearch] = useState('')
  const [selectedRule, setSelectedRule] = useState(null)
  const [ruleReviewerRole, setRuleReviewerRole] = useState('Analyst')
  const [investigationSearch, setInvestigationSearch] = useState('')
  const [investigationDecisionFilter, setInvestigationDecisionFilter] = useState('All')
  const [investigationSeverityFilter, setInvestigationSeverityFilter] = useState('All')

  const loadDashboard = useCallback(async ({ silent = false } = {}) => {
    if (dashboardRequestInFlight.current) return

    dashboardRequestInFlight.current = true
    if (!silent) setDashboardLoading(true)
    setDashboardError('')

    try {
      const endpoints = [
        '/api/v1/dashboard/summary',
        '/api/v1/alerts?limit=200',
        '/api/v1/incidents?limit=100',
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
      setAlerts(Array.isArray(payloads[1].alerts) ? payloads[1].alerts : [])
      setIncidents(Array.isArray(payloads[2].incidents) ? payloads[2].incidents : [])
      setInvestigations(
        Array.isArray(payloads[3].investigations)
          ? payloads[3].investigations
          : []
      )
    } catch (err) {
      setDashboardError(err.message || 'Could not load dashboard data.')
    } finally {
      dashboardRequestInFlight.current = false
      if (!silent) setDashboardLoading(false)
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
      setError(err.message || 'Could not connect to the response-actions API.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadActions()
    loadDashboard()

    const refreshInterval = window.setInterval(() => {
      loadDashboard({ silent: true })
    }, 5000)

    return () => window.clearInterval(refreshInterval)
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
          headers: { 'Content-Type': 'application/json' },
          ...(body ? { body: JSON.stringify(body) } : {}),
        }
      )
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        throw new Error(data.detail || `Action failed (HTTP ${response.status})`)
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
    )) return
    performAction(action, 'approve')
  }

  const deny = action => {
    const reason = window.prompt(
      'Why are you rejecting this action?\nMinimum 3 characters.'
    )
    if (reason === null) return
    if (reason.trim().length < 3) {
      setError('Please provide a rejection reason of at least 3 characters.')
      return
    }
    performAction(action, 'reject', { reason: reason.trim() })
  }

  const execute = action => {
    if (!window.confirm(
      `Request simulated execution of "${actionLabels[action.action_type] || action.action_type}: ${action.target}"?\n\nThis prototype is designed to simulate actions, not make real system changes.`
    )) return
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
    },
    {
      label: 'Critical Alerts',
      value: summary ? String(summary.critical_alerts ?? 0) : '—',
      delta: 'Wazuh level ≥ 12',
      color: 'green',
    },
    {
      label: 'Pending Review',
      value: summary ? String(summary.pending_review ?? 0) : '—',
      delta: dashboardLoading ? 'Loading' : 'Investigations',
      color: 'orange',
    },
    {
      label: 'Investigations',
      value: summary ? String(summary.total_investigations ?? 0) : '—',
      delta: dashboardLoading ? 'Loading' : 'PostgreSQL',
      color: 'cyan',
    },
  ]

  // Global review count comes from the backend summary.
  // Other activity metrics describe the investigations currently loaded.
  const timeline = [
    { label: 'Investigations loaded', value: investigations.length, type: 'scan' },
    { label: 'Require human review', value: summary?.pending_review ?? 0, type: 'escalate' },
    {
      label: 'True positive decisions (loaded)',
      value: investigations.filter(item => item.decision === 'True Positive').length,
      type: 'correlate',
    },
    {
      label: 'False positive decisions (loaded)',
      value: investigations.filter(item => item.decision === 'False Positive').length,
      type: 'resolve',
    },
    {
      label: 'Linked to incidents (loaded)',
      value: investigations.filter(item => item.incident_id != null).length,
      type: 'update',
    },
  ]

  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'alerts', label: 'Alerts' },
    { id: 'incidents', label: 'Incidents' },
    { id: 'investigations', label: 'Investigations' },
    { id: 'agents', label: 'Agents' },
    { id: 'playbooks', label: 'Playbooks' },
    { id: 'reports', label: 'Reports' },
  ]

  const pageMeta = {
    dashboard: ['Security Dashboard', 'Autonomous SOC · Human-Gated'],
    alerts: ['Security Alerts', 'Persisted Wazuh alerts and investigation decisions'],
    incidents: ['Incidents', 'Incident records stored by the SOC backend'],
    investigations: ['Investigation Centre', 'AI-assisted analysis, evidence decisions and investigation tracking'],
    agents: ['Agent & System Intelligence', 'AI agents, SOC processing components and endpoint visibility'],
    playbooks: ['SOC Rulebook & Playbooks', 'Detection rules, MITRE mappings, IOC intelligence and analyst governance'],
    reports: ['Security Reports', 'Metrics calculated from backend records'],
    settings: ['Settings', 'Application and integration configuration status'],
  }

  const [pageTitle, pageSubtitle] = pageMeta[nav] || pageMeta.dashboard

  const investigationForAlert = alert => investigations.find(
    item => Number(item.alert_database_id) === Number(alert.id)
  )

  const renderAlertRows = rows => (
    rows.length === 0 ? (
      <p>No persisted alerts are available.</p>
    ) : rows.map(alert => {
      const investigation = investigationForAlert(alert)
      const severity = severityForAlert(alert.rule_level)
      const source = alert.source_ip || alert.agent_name || alert.username || 'Source unavailable'
      return (
        <div key={alert.id} className={`alert-row ${severity}`}>
          <span className={`sev-dot ${severity}`} />
          <div className="alert-info">
            <span className="alert-title">
              {alert.rule_description || `Wazuh alert ${alert.wazuh_alert_id || alert.id}`}
            </span>
            <span className="alert-meta">
              {source} · Rule level {displayValue(alert.rule_level)} · {formatAlertTime(alert.timestamp)}
            </span>
            <span className="alert-meta">
              Investigation: {decisionLabel(investigation)}
              {investigation?.severity ? ` · AI severity: ${investigation.severity}` : ''}
            </span>
            {alert.wazuh_alert_id?.startsWith('VALIDATOR-') && (
              <span className="alert-meta">Synthetic validation event</span>
            )}
          </div>
          <div className="alert-row-actions">
            <span className={`tag ${investigation?.decision === 'True Positive' ? 'escalated' : investigation?.decision === 'False Positive' ? 'resolved' : 'pending'}`}>
              {investigation?.decision || 'Not investigated'}
            </span>
            <button
              type="button"
              className="btn alert-details-btn"
              onClick={() => setSelectedAlert(alert)}
            >
              Details
            </button>
            {localReviews[alert.id]?.decision ? (
              <span className={`tag ${localReviews[alert.id].decision === 'Approved' ? 'approved' : 'rejected'}`}>
                {localReviews[alert.id].decision} · Local
              </span>
            ) : (
              <div className="gate-btns alert-review-btns">
                <button
                  type="button"
                  className="btn ok"
                  onClick={() => {
                    if (!window.confirm('Approve this alert for the demo review record?')) return
                    setLocalReviews(previous => ({
                      ...previous,
                      [alert.id]: {
                        decision: 'Approved',
                        reviewer: reviewer || 'Local reviewer',
                        timestamp: new Date().toISOString(),
                        reason: 'Approved in frontend demo review',
                      },
                    }))
                  }}
                >
                  Approve
                </button>
                <button
                  type="button"
                  className="btn no"
                  onClick={() => {
                    const reason = window.prompt('Enter a reason for denying this alert:')
                    if (reason === null) return
                    if (reason.trim().length < 3) {
                      setError('Please enter a denial reason of at least 3 characters.')
                      return
                    }
                    setLocalReviews(previous => ({
                      ...previous,
                      [alert.id]: {
                        decision: 'Denied',
                        reviewer: reviewer || 'Local reviewer',
                        timestamp: new Date().toISOString(),
                        reason: reason.trim(),
                      },
                    }))
                  }}
                >
                  Deny
                </button>
              </div>
            )}
          </div>
        </div>
      )
    })
  )

  const renderDashboard = () => (
    <>
      <section className="stats">
        {stats.map(stat => (
          <article key={stat.label} className={`stat-card c-${stat.color}`}>
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
          {reviewer && <p className="gate-agent">Authenticated reviewer: {reviewer}</p>}
          <button className="btn" onClick={loadActions} disabled={loading || busyId !== null} style={{ marginBottom: 12 }}>
            {loading ? 'Refreshing…' : 'Refresh Actions'}
          </button>
          {loading && actions.length === 0 && <p>Loading persisted response actions…</p>}
          {!loading && actions.length === 0 && !error && <p>No response actions are currently recorded by the backend.</p>}
          {actions.map(action => {
            const status = String(action.status || '').toLowerCase()
            const risk = riskForAction(action)
            const isBusy = busyId === action.id
            return (
              <div key={action.id} className={`gate-row ${risk}`}>
                <div className="gate-info">
                  <span className={`risk ${risk}`}>{risk}</span>
                  <span className="gate-act">{actionLabels[action.action_type] || action.action_type} {action.target}</span>
                  <span className="gate-agent">Incident #{action.incident_id} · {statusLabel(action.status)}</span>
                  {action.result && <span className="gate-agent">{action.result}</span>}
                  {action.rejection_reason && <span className="gate-agent">Rejection reason: {action.rejection_reason}</span>}
                </div>
                {isBusy ? <span className="tag">Processing…</span> : status === 'pending' ? (
                  <div className="gate-btns">
                    <button className="btn ok" onClick={() => approve(action)}>Approve</button>
                    <button className="btn no" onClick={() => deny(action)}>Reject</button>
                  </div>
                ) : status === 'approved' ? (
                  <div className="gate-btns">
                    <span className="tag approved">Approved</span>
                    <button className="btn ok" onClick={() => execute(action)}>Run Simulation</button>
                  </div>
                ) : <span className={`tag ${status}`}>{statusLabel(action.status)}</span>}
              </div>
            )
          })}
        </section>

        <section className="card feed">
          <div className="card-head">
            <h3>Alert Feed · PostgreSQL</h3>
            <span className="pill">{alerts.length}</span>
          </div>
          {dashboardLoading && alerts.length === 0 && <p>Loading persisted alerts…</p>}
          {!dashboardLoading && dashboardError && <p role="alert">Could not load live alerts: {dashboardError}</p>}
          {!dashboardLoading && !dashboardError && alerts.length === 0 && <p>No alerts are currently stored in the database.</p>}
          {renderAlertRows(alerts.slice(0, 10))}
        </section>

        <section className="card tline">
          <div className="card-head"><h3>Investigation Activity · Live Data</h3></div>
          {dashboardLoading && <p>Loading investigation activity…</p>}
          {!dashboardLoading && dashboardError && <p role="alert">Could not load investigation activity: {dashboardError}</p>}
          {!dashboardLoading && !dashboardError && timeline.map(item => (
            <div key={item.label} className={`tl-row ${item.type}`}>
              <span className="tl-time">DB</span>
              <span className="tl-dot" />
              <span className="tl-event">{item.label}: <strong>{item.value}</strong></span>
            </div>
          ))}
          {!dashboardLoading && !dashboardError && (
            <p className="alert-meta">Counts reflect the investigation records loaded by the dashboard, not a chronological activity log.</p>
          )}
        </section>
      </div>
    </>
  )

  const renderAlerts = () => (
    <section className="card feed">
      <div className="card-head">
        <h3>Persisted Wazuh Alerts</h3>
        <span className="pill">{alerts.length} loaded</span>
      </div>
      {dashboardLoading ? <p>Loading alerts…</p> : dashboardError ? <p role="alert">{dashboardError}</p> : renderAlertRows(alerts)}
      <p className="alert-meta">Showing up to 200 alert records returned by the backend. Investigation decisions are matched using the alert database ID.</p>
    </section>
  )


  const renderIncidents = () => {
    const escalationFor = key => localEscalations.filter(item => item.key === key)

    const submitManualTicket = event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      const title = String(form.get('title') || '').trim()
      const description = String(form.get('description') || '').trim()
      if (!title || !description) return

      const ticket = {
        id: `MAN-${Date.now()}`,
        title,
        severity: String(form.get('severity') || 'Medium'),
        affected_system: String(form.get('affected_system') || '').trim(),
        source: String(form.get('source') || 'Other'),
        description,
        evidence: String(form.get('evidence') || '').trim(),
        reporter: String(form.get('reporter') || '').trim(),
        status: 'Open',
        created_at: new Date().toISOString(),
      }

      setManualTickets(previous => [ticket, ...previous])
      event.currentTarget.reset()
      setNotice(`Manual ticket ${ticket.id} created locally.`)
    }

    const submitEscalation = event => {
      event.preventDefault()
      if (!escalationTarget) return
      const form = new FormData(event.currentTarget)
      const reason = String(form.get('reason') || '').trim()
      if (reason.length < 5) return

      const record = {
        id: `ESC-${Date.now()}`,
        key: escalationTarget.key,
        incident: escalationTarget.label,
        level: String(form.get('level') || 'L2'),
        team: String(form.get('team') || 'SOC L2'),
        reason,
        notes: String(form.get('notes') || '').trim(),
        created_at: new Date().toISOString(),
      }

      setLocalEscalations(previous => [record, ...previous])
      setNotice(`${record.id} recorded locally. No external notification was sent.`)
      setEscalationTarget(null)
    }

    return (
      <>
        <section className="card outage-banner">
          <div className="outage-banner-icon">!</div>
          <div className="outage-banner-copy">
            <strong>System outage / manual operations mode</strong>
            <p>If Wazuh, SIEM, EDR, integrations, or the SOC platform are unavailable, record the incident manually and use the escalation workflow below.</p>
            <span>Fallback records are currently browser-session-only and are not persisted by the backend.</span>
          </div>
          <span className="tag pending">Fallback workflow</span>
        </section>

        <section className="card manual-ticket-card">
          <div className="card-head">
            <div>
              <h3>Create Manual Incident Ticket</h3>
              <p className="alert-meta">Use when automated alert ingestion or the incident platform is unavailable.</p>
            </div>
            <span className="tag pending">Manual entry</span>
          </div>

          <form className="manual-ticket-form" onSubmit={submitManualTicket}>
            <label>Incident title
              <input name="title" required maxLength="160" placeholder="e.g. Production server unavailable" />
            </label>
            <label>Severity
              <select name="severity" defaultValue="High">
                <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
              </select>
            </label>
            <label>Affected system / asset
              <input name="affected_system" placeholder="Hostname, application, network segment..." />
            </label>
            <label>Reported through
              <select name="source" defaultValue="Phone / verbal report">
                <option>Phone / verbal report</option>
                <option>Email</option>
                <option>Monitoring unavailable</option>
                <option>Service desk</option>
                <option>Other</option>
              </select>
            </label>
            <label className="form-wide">Incident description
              <textarea name="description" required rows="4" placeholder="What happened? When was it first observed? What is the impact?" />
            </label>
            <label className="form-wide">Evidence / indicators
              <textarea name="evidence" rows="3" placeholder="IPs, usernames, hostnames, timestamps, log excerpts or evidence location..." />
            </label>
            <label>Reported by
              <input name="reporter" placeholder="Analyst name / contact" />
            </label>
            <div className="manual-form-submit">
              <button className="btn primary" type="submit">Create manual ticket</button>
            </div>
          </form>
        </section>

        <section className="card">
          <div className="card-head">
            <h3>Persisted Incidents</h3>
            <span className="pill">{incidents.length} loaded</span>
          </div>
          {dashboardLoading ? <p>Loading incidents…</p> :
           dashboardError ? <p role="alert">{dashboardError}</p> :
           incidents.length === 0 ? <p>No incident records were returned by the backend.</p> : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr>
                  <th>Incident</th><th>Title</th><th>Severity</th>
                  <th>Status</th><th>Created</th><th>Escalation</th>
                </tr></thead>
                <tbody>
                  {incidents.map(incident => {
                    const key = `persisted-${incident.id}`
                    const count = escalationFor(key).length
                    return (
                      <tr key={incident.id}>
                        <td>{displayValue(incident.incident_number || incident.id)}</td>
                        <td>{displayValue(incident.title)}</td>
                        <td><span className={`tag ${String(incident.severity || '').toLowerCase()}`}>{displayValue(incident.severity)}</span></td>
                        <td>{displayValue(incident.status)}</td>
                        <td>{formatAlertTime(incident.created_at)}</td>
                        <td>
                          <button type="button" className="btn"
                            onClick={() => setEscalationTarget({
                              key, label: incident.incident_number || incident.title || incident.id
                            })}>Escalate</button>
                          {count > 0 && <span className="tag escalated">{count} local</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-head">
            <h3>Manually Created Tickets</h3>
            <span className="pill">{manualTickets.length} this session</span>
          </div>
          {manualTickets.length === 0 ? <p>No manual tickets created in this session.</p> : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr>
                  <th>Ticket</th><th>Title / affected system</th><th>Severity</th>
                  <th>Status</th><th>Created</th><th>Action</th>
                </tr></thead>
                <tbody>
                  {manualTickets.map(ticket => {
                    const key = `manual-${ticket.id}`
                    const count = escalationFor(key).length
                    return (
                      <tr key={ticket.id}>
                        <td>{ticket.id}<div className="manual-source-label">MANUAL</div></td>
                        <td><strong>{ticket.title}</strong><div className="alert-meta">{ticket.affected_system || 'Not specified'}</div></td>
                        <td><span className={`tag ${ticket.severity.toLowerCase()}`}>{ticket.severity}</span></td>
                        <td>{ticket.status}</td>
                        <td>{formatAlertTime(ticket.created_at)}</td>
                        <td>
                          <button type="button" className="btn"
                            onClick={() => setEscalationTarget({key, label: ticket.id})}>Escalate</button>
                          {count > 0 && <span className="tag escalated">{count} local</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
          {manualTickets.length > 0 && (
            <div className="manual-ticket-details">
              {manualTickets.map(ticket => (
                <details key={`${ticket.id}-details`}>
                  <summary>{ticket.id} — {ticket.title}</summary>
                  <p>{ticket.description}</p>
                  <p><strong>Reported via:</strong> {ticket.source} · <strong>Reporter:</strong> {ticket.reporter || 'Not specified'}</p>
                  {ticket.evidence && <p><strong>Evidence:</strong> {ticket.evidence}</p>}
                </details>
              ))}
            </div>
          )}
        </section>

        {escalationTarget && (
          <section className="card escalation-card">
            <div className="card-head">
              <div><h3>Escalate Incident</h3><p className="alert-meta">Target: {escalationTarget.label}</p></div>
              <button type="button" className="btn" onClick={() => setEscalationTarget(null)}>Cancel</button>
            </div>
            <form className="manual-ticket-form" onSubmit={submitEscalation}>
              <label>Escalation level
                <select name="level" defaultValue="L2">
                  <option>L2</option><option>L3</option>
                  <option>Incident Response Team</option><option>Management</option>
                </select>
              </label>
              <label>Destination team
                <select name="team" defaultValue="SOC L2">
                  <option>SOC L2</option><option>SOC L3</option>
                  <option>Incident Response Team</option><option>IT Infrastructure</option>
                  <option>Network Operations</option><option>Management</option>
                </select>
              </label>
              <label className="form-wide">Reason for escalation
                <textarea name="reason" required minLength="5" rows="3" placeholder="Why does this incident require escalation?" />
              </label>
              <label className="form-wide">Handover notes / actions taken
                <textarea name="notes" rows="3" placeholder="Containment attempted, evidence collected, systems affected..." />
              </label>
              <div className="manual-form-submit">
                <button className="btn primary" type="submit">Record escalation</button>
              </div>
            </form>
          </section>
        )}

        <section className="card">
          <div className="card-head">
            <h3>Escalation Activity</h3>
            <span className="pill">{localEscalations.length} local records</span>
          </div>
          {localEscalations.length === 0 ? <p>No escalation recorded in this session.</p> : (
            <div className="escalation-list">
              {localEscalations.map(item => (
                <article className="escalation-item" key={item.id}>
                  <div><strong>{item.incident}</strong><span className="tag escalated">{item.level} · {item.team}</span></div>
                  <p>{item.reason}</p>
                  {item.notes && <p className="alert-meta">Handover: {item.notes}</p>}
                  <span className="alert-meta">{item.id} · {formatAlertTime(item.created_at)} · Local record only</span>
                </article>
              ))}
            </div>
          )}
          <p className="alert-meta">No email, paging, or backend incident update is sent by this demo workflow. Those integrations require the backend phase.</p>
        </section>
      </>
    )
  }

  const renderInvestigations = () => {
    const filtered = investigations.filter(item => {
      const search = investigationSearch.trim().toLowerCase()
      const searchable = [
        item.id,
        item.alert_database_id,
        item.incident_id,
        item.decision,
        item.severity,
        item.confidence,
        item.investigation_status,
        item.investigation_type,
        item.error,
      ].filter(Boolean).join(' ').toLowerCase()

      return (!search || searchable.includes(search)) &&
        (investigationDecisionFilter === 'All' || item.decision === investigationDecisionFilter) &&
        (investigationSeverityFilter === 'All' || item.severity === investigationSeverityFilter)
    })

    const truePositives = investigations.filter(item => item.decision === 'True Positive').length
    const falsePositives = investigations.filter(item => item.decision === 'False Positive').length
    const uncertain = investigations.filter(item => !['True Positive', 'False Positive'].includes(item.decision)).length
    const completed = investigations.filter(item => item.investigation_status === 'Completed').length
    const failed = investigations.filter(item => item.investigation_status === 'Failed' || Boolean(item.error)).length

    const decisionClass = decision => {
      if (decision === 'True Positive') return 'escalated'
      if (decision === 'False Positive') return 'resolved'
      return 'pending'
    }

    const severityClass = severity => String(severity || '').toLowerCase()

    return (
      <>
        <section className="stats investigation-kpis">
          <article className="stat-card c-cyan"><div className="stat-body"><span className="stat-val">{investigations.length}</span><span className="stat-lbl">Loaded investigations</span></div></article>
          <article className="stat-card c-red"><div className="stat-body"><span className="stat-val">{truePositives}</span><span className="stat-lbl">True positives</span></div></article>
          <article className="stat-card c-green"><div className="stat-body"><span className="stat-val">{falsePositives}</span><span className="stat-lbl">False positives</span></div></article>
          <article className="stat-card c-orange"><div className="stat-body"><span className="stat-val">{uncertain}</span><span className="stat-lbl">Uncertain / other</span></div></article>
        </section>

        <section className="card investigation-overview">
          <div className="card-head">
            <div>
              <h3>Investigation workload</h3>
              <p className="alert-meta">Operational summary of the investigation records returned by the backend.</p>
            </div>
            <span className="pill">{investigations.length} loaded</span>
          </div>
          <div className="investigation-status-strip">
            <div><span className="status-indicator completed" /><span>Completed</span><strong>{completed}</strong></div>
            <div><span className="status-indicator failed" /><span>Failed</span><strong>{failed}</strong></div>
            <div><span className="status-indicator review" /><span>Require human review</span><strong>{displayValue(summary?.pending_review)}</strong></div>
          </div>
          <p className="alert-meta">Human-review count is the backend-wide summary. Other counts describe the investigations currently loaded.</p>
        </section>

        <section className="card investigation-list-card">
          <div className="card-head">
            <div>
              <h3>Investigation records</h3>
              <p className="alert-meta">Search, filter and inspect investigation outcomes.</p>
            </div>
            <span className="pill">{filtered.length} shown / {investigations.length} loaded</span>
          </div>

          <div className="investigation-toolbar">
            <input
              type="search"
              className="investigation-search"
              placeholder="Search investigation, alert ID, incident, decision..."
              value={investigationSearch}
              onChange={event => setInvestigationSearch(event.target.value)}
              aria-label="Search investigations"
            />
            <select
              className="investigation-filter"
              value={investigationDecisionFilter}
              onChange={event => setInvestigationDecisionFilter(event.target.value)}
              aria-label="Filter by decision"
            >
              <option value="All">All decisions</option>
              <option value="True Positive">True Positive</option>
              <option value="False Positive">False Positive</option>
              <option value="Uncertain">Uncertain</option>
            </select>
            <select
              className="investigation-filter"
              value={investigationSeverityFilter}
              onChange={event => setInvestigationSeverityFilter(event.target.value)}
              aria-label="Filter by severity"
            >
              <option value="All">All severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
            <button
              type="button"
              className="btn"
              onClick={() => {
                setInvestigationSearch('')
                setInvestigationDecisionFilter('All')
                setInvestigationSeverityFilter('All')
              }}
            >Reset</button>
          </div>

          {dashboardLoading ? (
            <p>Loading investigation records…</p>
          ) : dashboardError ? (
            <p role="alert">{dashboardError}</p>
          ) : filtered.length === 0 ? (
            <div className="investigation-empty">
              <strong>No matching investigations</strong>
              <p>Try changing the search term or filters.</p>
            </div>
          ) : (
            <div className="investigation-record-list">
              {filtered.map(item => (
                <article className="investigation-record" key={item.id}>
                  <div className="investigation-record-main">
                    <div className="investigation-record-heading">
                      <strong>INV-{item.id}</strong>
                      <span className={`tag ${decisionClass(item.decision)}`}>{displayValue(item.decision)}</span>
                      <span className={`tag ${severityClass(item.severity)}`}>{displayValue(item.severity)}</span>
                    </div>
                    <div className="investigation-record-links">
                      <span>Alert DB ID: <strong>{displayValue(item.alert_database_id)}</strong></span>
                      <span>Incident ID: <strong>{displayValue(item.incident_id)}</strong></span>
                      <span>Type: <strong>{displayValue(item.investigation_type)}</strong></span>
                    </div>
                  </div>
                  <div className="investigation-record-metrics">
                    <div><span>Confidence</span><strong>{displayValue(item.confidence)}</strong></div>
                    <div><span>Status</span><strong>{displayValue(item.investigation_status)}</strong></div>
                    <div><span>Completed</span><strong>{formatAlertTime(item.completed_at)}</strong></div>
                  </div>
                  {item.error && (
                    <div className="investigation-error">
                      <strong>Investigation error</strong>
                      <p>{item.error}</p>
                    </div>
                  )}
                  {item.human_review_required && (
                    <div className="investigation-review-notice">
                      <span className="tag pending">Human review required</span>
                      <span>Analyst review is required before relying on this result for consequential action.</span>
                    </div>
                  )}
                </article>
              ))}
            </div>
          )}
          <p className="alert-meta investigation-scope-note">
            Showing up to 100 investigation records returned by the current API. This view displays persisted investigation metadata; detailed model reasoning and evidence are not currently exposed by the investigation-list endpoint.
          </p>
        </section>
      </>
    )
  }

  const renderAgents = () => {
    const agentCards = [
      {
        name: 'Tiny CyberLLM',
        type: 'Custom cybersecurity language model',
        role: 'Experimental custom model developed for SOC alert interpretation and cybersecurity-focused analysis.',
        status: 'Experimental',
        tone: 'warning',
        detail: 'Generation quality is still under evaluation. Do not treat its output as independently verified analyst conclusions.',
        icon: 'brain',
      },
      {
        name: 'Qwen Verification Model',
        type: 'Secondary AI analysis',
        role: 'Provides a secondary investigation perspective and cross-verification of alert analysis.',
        status: 'Integrated',
        tone: 'info',
        detail: 'Verification can be affected by model response latency and timeouts. Its output is subject to evidence validation.',
        icon: 'shield-check',
      },
      {
        name: 'AI Investigation Worker',
        type: 'Background processing worker',
        role: 'Consumes investigation jobs, coordinates model analysis, validates results and persists investigation outcomes.',
        status: 'Container deployed',
        tone: 'success',
        detail: 'Runs as the separate ai-worker service. Container availability does not guarantee every AI investigation succeeds.',
        icon: 'workflow',
      },
    ]

    const processingCards = [
      {
        name: 'Alert Ingestion & Normalization',
        role: 'Receives Wazuh alerts, normalizes event fields and persists alert records.',
        status: 'Implemented',
        tone: 'success',
      },
      {
        name: 'SOC Rulebook',
        role: 'Applies deterministic SOC rules and matching logic during alert processing.',
        status: 'Implemented',
        tone: 'success',
      },
      {
        name: 'RAG / FAISS Knowledge Retrieval',
        role: 'Retrieves relevant cybersecurity context to support investigation workflows.',
        status: 'Integrated',
        tone: 'info',
      },
      {
        name: 'Alert Correlation',
        role: 'Evaluates related alert context to support investigation and prioritization.',
        status: 'Implemented',
        tone: 'success',
      },
      {
        name: 'Threat Intelligence Enrichment',
        role: 'Supports IOC and threat-context enrichment in the investigation architecture.',
        status: 'Pipeline component',
        tone: 'info',
      },
      {
        name: 'MITRE ATT&CK Mapping',
        role: 'Associates alert evidence with relevant ATT&CK techniques where mapping data is available.',
        status: 'Integrated',
        tone: 'info',
      },
      {
        name: 'Evidence Validator',
        role: 'Checks whether investigation claims are supported by the available alert evidence.',
        status: 'Implemented',
        tone: 'success',
      },
      {
        name: 'Human Review Gate',
        role: 'Keeps analyst approval in the decision workflow before consequential response actions.',
        status: 'Implemented',
        tone: 'success',
      },
      {
        name: 'Response Action Engine',
        role: 'Manages human-approved response proposals and simulated execution workflow.',
        status: 'Simulation only',
        tone: 'warning',
      },
    ]

    return (
      <>
        <section className="agent-overview-grid">
          <article className="agent-overview-card">
            <span className="agent-overview-label">AI AGENTS</span>
            <strong>{agentCards.length}</strong>
            <span>Model and worker components</span>
          </article>
          <article className="agent-overview-card">
            <span className="agent-overview-label">SOC COMPONENTS</span>
            <strong>{processingCards.length}</strong>
            <span>Processing and control services</span>
          </article>
          <article className="agent-overview-card">
            <span className="agent-overview-label">LOADED ALERTS</span>
            <strong>{alerts.length}</strong>
            <span>Records returned by backend</span>
          </article>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>AI Agents & Model Services</h3>
              <p className="alert-meta">Intelligent analysis and background investigation components.</p>
            </div>
            <span className="tag info">AI layer</span>
          </div>
          <div className="agent-card-grid">
            {agentCards.map((agent, index) => (
              <article className="agent-component-card" key={agent.name}>
                <div className="agent-component-top">
                  <span className="agent-component-icon">
                    {index === 0 ? 'AI' : index === 1 ? 'QV' : 'WK'}
                  </span>
                  <span className={`tag ${agent.tone}`}>{agent.status}</span>
                </div>
                <h4>{agent.name}</h4>
                <span className="agent-component-type">{agent.type}</span>
                <p>{agent.role}</p>
                <details>
                  <summary>Operational notes</summary>
                  <p>{agent.detail}</p>
                </details>
              </article>
            ))}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>SOC Processing Components</h3>
              <p className="alert-meta">Supporting services, analysis stages and human-control mechanisms.</p>
            </div>
            <span className="tag info">Processing layer</span>
          </div>
          <div className="agent-processing-list">
            {processingCards.map(component => (
              <article className="agent-processing-row" key={component.name}>
                <div className="agent-processing-mark" />
                <div className="agent-processing-copy">
                  <strong>{component.name}</strong>
                  <p>{component.role}</p>
                </div>
                <span className={`tag ${component.tone}`}>{component.status}</span>
              </article>
            ))}
          </div>
          <p className="alert-meta">
            Status labels describe the current implementation stage. They are not live service-health checks unless explicitly connected to runtime monitoring.
          </p>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Wazuh Endpoint Inventory</h3>
              <p className="alert-meta">Monitored endpoint visibility and Wazuh integration status.</p>
            </div>
            <span className="tag pending">Inventory API unavailable</span>
          </div>
          <p>The application receives Wazuh alerts through the manager integration webhook and persists them through the FastAPI backend.</p>
          <p>Wazuh API authentication has previously been verified from the backend container. However, the frontend does not currently have an authenticated agent-inventory endpoint.</p>
          <div className="stats">
            <article className="stat-card">
              <div className="stat-body">
                <span className="stat-val">{alerts.length}</span>
                <span className="stat-lbl">Loaded alerts</span>
              </div>
            </article>
            <article className="stat-card">
              <div className="stat-body">
                <span className="stat-val">—</span>
                <span className="stat-lbl">Agent inventory</span>
              </div>
            </article>
          </div>
          <p className="alert-meta">
            No endpoint names, IDs, operating systems or connection states are fabricated. A dedicated authenticated backend endpoint is required for live inventory.
          </p>
        </section>
      </>
    )
  }


  const renderPlaybooks = () => {
    // Only BRUTE_FORCE is confirmed as implemented by the current
    // RulebookEngine and the project history. Other use cases are proposals.
    const ruleCatalogue = [
      {
        id: 'BRUTE_FORCE',
        name: 'Brute Force Authentication',
        category: 'Authentication',
        severity: 'High',
        status: 'Implemented',
        description: 'Multiple failed authentication attempts from the same source.',
        wazuhIds: ['5710', '5760'],
        keywords: ['failed password', 'failed authentication', 'authentication failure', 'brute force'],
        mitre: {
          tactics: ['Credential Access'],
          techniques: ['T1110'],
          subtechniques: ['T1110.001'],
        },
        collect: ['source_ip', 'username', 'timestamp', 'authentication_logs'],
        source: 'configs/soc_rulebook.yaml',
      },
      {
        id: 'MALWARE',
        name: 'Malware Detection',
        category: 'Malware',
        severity: 'Critical',
        status: 'Planned',
        description: 'Detection of potentially malicious software or activity.',
        wazuhIds: [],
        keywords: ['malware', 'trojan', 'ransomware', 'virus'],
        mitre: { tactics: ['Execution', 'Persistence'], techniques: [], subtechniques: [] },
        collect: ['file_name', 'file_hash', 'process_name', 'parent_process', 'source_ip'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'SUSPICIOUS_POWERSHELL',
        name: 'Suspicious PowerShell',
        category: 'Execution',
        severity: 'High',
        status: 'Planned',
        description: 'Potentially suspicious PowerShell execution and command activity.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Execution'], techniques: [], subtechniques: [] },
        collect: ['process_command_line', 'user', 'parent_process', 'timestamp'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'PRIVILEGE_ESCALATION',
        name: 'Privilege Escalation',
        category: 'Privilege',
        severity: 'Critical',
        status: 'Planned',
        description: 'Potential attempts to gain elevated privileges.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Privilege Escalation'], techniques: [], subtechniques: [] },
        collect: ['user', 'process', 'privilege_change', 'timestamp'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'IMPOSSIBLE_LOGIN',
        name: 'Impossible Login',
        category: 'Authentication',
        severity: 'High',
        status: 'Planned',
        description: 'Potentially inconsistent login locations or travel patterns.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Initial Access', 'Credential Access'], techniques: [], subtechniques: [] },
        collect: ['username', 'source_ip', 'geolocation', 'login_timestamp'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'PORT_SCANNING',
        name: 'Port Scanning',
        category: 'Network',
        severity: 'Medium',
        status: 'Planned',
        description: 'Potential network reconnaissance through port scanning.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Reconnaissance', 'Discovery'], techniques: [], subtechniques: [] },
        collect: ['source_ip', 'destination_ip', 'destination_port', 'network_flow'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'SUSPICIOUS_NETWORK_ACTIVITY',
        name: 'Suspicious Network Activity',
        category: 'Network',
        severity: 'High',
        status: 'Planned',
        description: 'Network activity requiring additional security investigation.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Command and Control', 'Discovery'], techniques: [], subtechniques: [] },
        collect: ['source_ip', 'destination_ip', 'destination_port', 'protocol', 'timestamp'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'LATERAL_MOVEMENT',
        name: 'Lateral Movement',
        category: 'Lateral Movement',
        severity: 'High',
        status: 'Planned',
        description: 'Potential movement between systems within an environment.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Lateral Movement'], techniques: [], subtechniques: [] },
        collect: ['source_host', 'destination_host', 'username', 'authentication_logs'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'DATA_EXFILTRATION',
        name: 'Data Exfiltration',
        category: 'Data Security',
        severity: 'Critical',
        status: 'Planned',
        description: 'Potential unauthorized transfer of sensitive data.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Exfiltration'], techniques: [], subtechniques: [] },
        collect: ['source_host', 'destination_ip', 'bytes_transferred', 'file_metadata'],
        source: 'Project use-case catalogue',
      },
      {
        id: 'ACTIVE_DIRECTORY',
        name: 'Active Directory Security',
        category: 'Identity',
        severity: 'High',
        status: 'Planned',
        description: 'Identity and directory-service events requiring investigation.',
        wazuhIds: [],
        keywords: [],
        mitre: { tactics: ['Credential Access', 'Persistence'], techniques: [], subtechniques: [] },
        collect: ['account_name', 'domain_controller', 'group_changes', 'authentication_logs'],
        source: 'Project use-case catalogue',
      },
    ]

    const categories = [
      'All', 'Authentication', 'Malware', 'Execution', 'Privilege',
      'Network', 'Lateral Movement', 'Data Security', 'Identity',
    ]

    const normalizedSearch = ruleSearch.trim().toLowerCase()
    const filteredRules = ruleCatalogue.filter(rule => {
      const categoryMatch =
        ruleCategoryFilter === 'All' || rule.category === ruleCategoryFilter
      const searchMatch = !normalizedSearch || [
        rule.id, rule.name, rule.description, rule.category,
        rule.severity, ...rule.wazuhIds, ...rule.keywords,
        ...rule.mitre.tactics, ...rule.mitre.techniques,
        ...rule.mitre.subtechniques,
      ].join(' ').toLowerCase().includes(normalizedSearch)
      return categoryMatch && searchMatch
    })

    const implementedCount = ruleCatalogue.filter(rule => rule.status === 'Implemented').length
    const pendingCount = ruleSubmissions.filter(item => item.status === 'Pending approval').length
    const approvedCount = ruleSubmissions.filter(item => item.status === 'Approved').length

    const submitRule = event => {
      event.preventDefault()
      const form = new FormData(event.currentTarget)
      const name = String(form.get('ruleName') || '').trim()
      const description = String(form.get('ruleDescription') || '').trim()
      const category = String(form.get('ruleCategory') || '').trim()
      const source = String(form.get('discoverySource') || '').trim()
      const severity = String(form.get('ruleSeverity') || 'Medium')
      const evidence = String(form.get('ruleEvidence') || '').trim()
      const mitre = String(form.get('ruleMitre') || '').trim()
      const indicators = String(form.get('ruleIndicators') || '').trim()
      const response = String(form.get('ruleResponse') || '').trim()

      if (name.length < 3 || description.length < 10 || evidence.length < 10) {
        setNotice('Provide a rule name, a meaningful description and supporting evidence.')
        return
      }

      const submission = {
        id: `RULE-${Date.now()}`,
        name,
        description,
        category,
        source,
        severity,
        evidence,
        mitre,
        indicators,
        response,
        submittedBy: reviewer || 'Local analyst',
        submittedAt: new Date().toISOString(),
        status: 'Pending approval',
        reviewer: null,
        reviewNote: '',
      }

      setRuleSubmissions(previous => [submission, ...previous])
      setNotice(`${submission.id} submitted to the local approval queue. It has not been activated in the SOC rulebook.`)
      event.currentTarget.reset()
    }

    const reviewSubmission = (id, decision) => {
      if (!['SOC Manager', 'Administrator'].includes(ruleReviewerRole)) {
        setNotice('Only the SOC Manager or Administrator role can review submissions in this prototype.')
        return
      }

      const note = window.prompt(
        decision === 'Approved'
          ? 'Approval note (optional):'
          : decision === 'Rejected'
            ? 'Reason for rejection:'
            : 'Changes requested from analyst:'
      )
      if (note === null) return
      if (decision !== 'Approved' && note.trim().length < 3) {
        setNotice('Please provide a review note of at least 3 characters.')
        return
      }

      setRuleSubmissions(previous => previous.map(item =>
        item.id === id
          ? {
              ...item,
              status: decision,
              reviewer: reviewer || ruleReviewerRole,
              reviewerRole: ruleReviewerRole,
              reviewedAt: new Date().toISOString(),
              reviewNote: note.trim() || 'Approved without additional note',
            }
          : item
      ))
      setNotice(`${id}: ${decision} recorded in local prototype state. No production rule was changed.`)
    }

    const statusClass = status => {
      if (status === 'Implemented' || status === 'Approved') return 'approved'
      if (status === 'Rejected') return 'denied'
      if (status === 'Planned') return 'info'
      return 'pending'
    }

    return (
      <>
        <section className="rulebook-stats">
          <article className="rulebook-stat">
            <span>CATALOGUE USE CASES</span>
            <strong>{ruleCatalogue.length}</strong>
            <small>Documented project use cases</small>
          </article>
          <article className="rulebook-stat">
            <span>IMPLEMENTED RULES</span>
            <strong>{implementedCount}</strong>
            <small>Confirmed in current rulebook</small>
          </article>
          <article className="rulebook-stat">
            <span>PENDING APPROVAL</span>
            <strong>{pendingCount}</strong>
            <small>Local analyst submissions</small>
          </article>
          <article className="rulebook-stat">
            <span>APPROVED SUBMISSIONS</span>
            <strong>{approvedCount}</strong>
            <small>Not yet activated in backend</small>
          </article>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Detection Rule Catalogue</h3>
              <p className="alert-meta">Search rules by name, ID, category, severity, indicator or MITRE technique.</p>
            </div>
            <span className="pill">{filteredRules.length} shown / {ruleCatalogue.length}</span>
          </div>

          <div className="rulebook-filters">
            <input
              type="search"
              value={ruleSearch}
              onChange={event => setRuleSearch(event.target.value)}
              placeholder="Search rule, keyword, Wazuh ID, MITRE..."
              aria-label="Search rules"
            />
            <select
              value={ruleCategoryFilter}
              onChange={event => setRuleCategoryFilter(event.target.value)}
              aria-label="Filter rules by category"
            >
              {categories.map(category => <option key={category}>{category}</option>)}
            </select>
          </div>

          <div className="rulebook-category-strip">
            {categories.map(category => (
              <button
                type="button"
                key={category}
                className={`rule-category-chip ${ruleCategoryFilter === category ? 'active' : ''}`}
                onClick={() => setRuleCategoryFilter(category)}
              >{category}</button>
            ))}
          </div>

          <div className="table-wrap">
            <table className="data-table rulebook-table">
              <thead>
                <tr>
                  <th>Rule ID / Name</th>
                  <th>Category</th>
                  <th>Severity</th>
                  <th>MITRE</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map(rule => (
                  <tr key={rule.id}>
                    <td>
                      <strong>{rule.name}</strong>
                      <small className="rule-id-label">{rule.id}</small>
                    </td>
                    <td>{rule.category}</td>
                    <td><span className={`tag ${rule.severity.toLowerCase()}`}>{rule.severity}</span></td>
                    <td>{rule.mitre.techniques.length ? rule.mitre.techniques.join(', ') : 'Not mapped'}</td>
                    <td><span className={`tag ${statusClass(rule.status)}`}>{rule.status}</span></td>
                    <td>
                      <button type="button" className="btn rule-view-btn" onClick={() => setSelectedRule(rule)}>
                        View
                      </button>
                    </td>
                  </tr>
                ))}
                {filteredRules.length === 0 && (
                  <tr><td colSpan="6">No catalogue entries match this search.</td></tr>
                )}
              </tbody>
            </table>
          </div>
          <p className="alert-meta">
            Catalogue source: current RulebookEngine configuration and project use-case list. Only the Brute Force rule is confirmed as implemented. Planned entries are not active detections.
          </p>
        </section>

        {selectedRule && (
          <section className="card rule-detail-panel">
            <div className="card-head">
              <div>
                <h3>{selectedRule.name}</h3>
                <p className="alert-meta">{selectedRule.id} · {selectedRule.category}</p>
              </div>
              <button type="button" className="btn" onClick={() => setSelectedRule(null)}>Close</button>
            </div>
            <p>{selectedRule.description}</p>
            <div className="rule-detail-grid">
              <div><label>Severity</label><strong>{selectedRule.severity}</strong></div>
              <div><label>Implementation</label><strong>{selectedRule.status}</strong></div>
              <div><label>Wazuh rule IDs</label><strong>{selectedRule.wazuhIds.join(', ') || 'Not configured'}</strong></div>
              <div><label>Source</label><strong>{selectedRule.source}</strong></div>
            </div>
            <h4>Detection indicators / keywords</h4>
            <div className="rule-token-list">
              {selectedRule.keywords.length
                ? selectedRule.keywords.map(item => <span key={item}>{item}</span>)
                : <span>Not configured</span>}
            </div>
            <h4>MITRE ATT&CK mapping</h4>
            <p>Tactics: {selectedRule.mitre.tactics.join(', ') || 'Not mapped'}</p>
            <p>Techniques: {selectedRule.mitre.techniques.join(', ') || 'Not mapped'}</p>
            <p>Sub-techniques: {selectedRule.mitre.subtechniques.join(', ') || 'Not mapped'}</p>
            <h4>Evidence to collect</h4>
            <div className="rule-token-list">
              {selectedRule.collect.map(item => <span key={item}>{item}</span>)}
            </div>
          </section>
        )}

        <section className="card">
          <div className="card-head">
            <div>
              <h3>MITRE ATT&CK Coverage</h3>
              <p className="alert-meta">Mappings explicitly present in the implemented rulebook entry.</p>
            </div>
            <span className="tag info">ATT&CK</span>
          </div>
          <div className="mitre-coverage-row">
            <div>
              <strong>Credential Access</strong>
              <p>Brute Force Authentication · {implementedCount ? 'BRUTE_FORCE' : 'No implemented mapping'}</p>
            </div>
            <div className="rule-token-list">
              <span>T1110</span>
              <span>T1110.001</span>
            </div>
          </div>
          <p className="alert-meta">
            Other use-case mappings remain unconfigured until verified and added to the active rulebook.
          </p>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>IOC Intelligence Library</h3>
              <p className="alert-meta">Indicator records for IP addresses, domains, URLs, file hashes and other observables.</p>
            </div>
            <span className="tag pending">No IOC catalogue API</span>
          </div>
          <div className="ioc-type-grid">
            {['IPv4 / IPv6', 'Domains', 'URLs', 'File hashes', 'Email addresses', 'Other observables'].map(type => (
              <div key={type}><strong>{type}</strong><span>Awaiting IOC records</span></div>
            ))}
          </div>
          <p className="alert-meta">
            No indicators are fabricated. IOC ingestion, source attribution, confidence, expiry, allowlisting and blocklist lifecycle require a dedicated backend data model.
          </p>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Submit Detection Rule / SOC Use Case</h3>
              <p className="alert-meta">Submit findings from threat hunting, unknown incidents, vulnerability research or operational observations.</p>
            </div>
            <span className="tag pending">Analyst submission</span>
          </div>
          <form className="rule-submission-form" onSubmit={submitRule}>
            <label>
              Rule / use-case name
              <input name="ruleName" required minLength="3" placeholder="e.g. Suspicious service creation" />
            </label>
            <label>
              Category
              <select name="ruleCategory" required defaultValue="Authentication">
                {categories.filter(item => item !== 'All').map(item => <option key={item}>{item}</option>)}
                <option>MITRE ATT&CK</option>
                <option>IOC Intelligence</option>
                <option>Vulnerability</option>
                <option>Threat Hunting</option>
                <option>Other</option>
              </select>
            </label>
            <label>
              Discovery source
              <select name="discoverySource" required defaultValue="Threat hunting">
                <option>Threat hunting</option>
                <option>Unknown / unclassified incident</option>
                <option>Vulnerability discovery</option>
                <option>IOC / threat intelligence</option>
                <option>Security audit</option>
                <option>Existing alert investigation</option>
                <option>Other</option>
              </select>
            </label>
            <label>
              Proposed severity
              <select name="ruleSeverity" defaultValue="Medium">
                <option>Critical</option><option>High</option><option>Medium</option><option>Low</option>
              </select>
            </label>
            <label className="form-wide">
              Description and detection objective
              <textarea name="ruleDescription" required minLength="10" rows="3" placeholder="What activity should this rule identify, and why?" />
            </label>
            <label className="form-wide">
              Supporting evidence / hunting findings
              <textarea name="ruleEvidence" required minLength="10" rows="4" placeholder="Include event IDs, log excerpts, affected assets, timestamps, observed behavior and validation steps. Avoid secrets." />
            </label>
            <label>
              MITRE ATT&CK technique(s)
              <input name="ruleMitre" placeholder="e.g. T1059.001 (if verified)" />
            </label>
            <label>
              Detection indicators / IOC values
              <input name="ruleIndicators" placeholder="Keywords, Wazuh IDs, IPs, hashes..." />
            </label>
            <label className="form-wide">
              Suggested investigation / response
              <textarea name="ruleResponse" rows="2" placeholder="Evidence to collect, analyst checks and recommended response." />
            </label>
            <div className="form-wide rule-submit-footer">
              <p className="alert-meta">Submission enters the local approval queue. It does not modify configs/soc_rulebook.yaml or activate a detection.</p>
              <button type="submit" className="btn primary">Submit for SOC Manager approval</button>
            </div>
          </form>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Rule Approval & Governance Queue</h3>
              <p className="alert-meta">Review proposed detection content before any production rulebook change.</p>
            </div>
            <span className="pill">{pendingCount} awaiting review</span>
          </div>
          <div className="rule-review-toolbar">
            <label>
              Prototype reviewer role
              <select value={ruleReviewerRole} onChange={event => setRuleReviewerRole(event.target.value)}>
                <option>Analyst</option>
                <option>SOC Manager</option>
                <option>Administrator</option>
              </select>
            </label>
            <span className="tag pending">Demo role selector · Not authentication</span>
          </div>

          {ruleSubmissions.length === 0 ? (
            <p>No analyst submissions yet. New proposals will appear here.</p>
          ) : (
            <div className="rule-submission-list">
              {ruleSubmissions.map(item => (
                <article className="rule-submission-item" key={item.id}>
                  <div className="rule-submission-heading">
                    <div>
                      <strong>{item.name}</strong>
                      <small>{item.id} · {item.category} · {item.severity}</small>
                    </div>
                    <span className={`tag ${statusClass(item.status)}`}>{item.status}</span>
                  </div>
                  <p>{item.description}</p>
                  <div className="rule-submission-meta">
                    <span>Source: {item.source}</span>
                    <span>Submitted by: {item.submittedBy}</span>
                    <span>{formatAlertTime(item.submittedAt)}</span>
                  </div>
                  <details>
                    <summary>Review submission evidence</summary>
                    <p><strong>Evidence:</strong> {item.evidence}</p>
                    <p><strong>MITRE:</strong> {item.mitre || 'Not supplied'}</p>
                    <p><strong>Indicators:</strong> {item.indicators || 'Not supplied'}</p>
                    <p><strong>Response:</strong> {item.response || 'Not supplied'}</p>
                    {item.reviewNote && <p><strong>Review note:</strong> {item.reviewNote}</p>}
                    {item.reviewer && <p><strong>Reviewed by:</strong> {item.reviewer} ({item.reviewerRole})</p>}
                  </details>
                  {item.status === 'Pending approval' && (
                    <div className="rule-review-actions">
                      <button type="button" className="btn ok" onClick={() => reviewSubmission(item.id, 'Approved')}>Approve</button>
                      <button type="button" className="btn" onClick={() => reviewSubmission(item.id, 'Changes requested')}>Request changes</button>
                      <button type="button" className="btn no" onClick={() => reviewSubmission(item.id, 'Rejected')}>Reject</button>
                    </div>
                  )}
                  {item.status === 'Approved' && (
                    <p className="alert-meta">Approved in prototype only. A separate implementation and deployment process is still required.</p>
                  )}
                </article>
              ))}
            </div>
          )}
        </section>

        <section className="card">
          <div className="card-head"><h3>Governance & Implementation Lifecycle</h3><span className="tag info">Target workflow</span></div>
          <div className="rule-lifecycle">
            {[
              ['01', 'Analyst discovery', 'Threat hunt, incident investigation, vulnerability or IOC discovery.'],
              ['02', 'Rule proposal', 'Document detection logic, indicators, evidence, severity and MITRE mapping.'],
              ['03', 'SOC Manager / Admin review', 'Validate evidence, false-positive risk, scope and operational impact.'],
              ['04', 'Controlled implementation', 'Update the rulebook through a reviewed change and test process.'],
              ['05', 'Validation & monitoring', 'Run unit tests and controlled alert tests, then monitor detection quality.'],
            ].map(step => (
              <div className="rule-lifecycle-step" key={step[0]}>
                <span>{step[0]}</span><div><strong>{step[1]}</strong><p>{step[2]}</p></div>
              </div>
            ))}
          </div>
          <p className="alert-meta">
            Current limitation: this page stores submissions and reviews in browser memory only. Role selection is demonstrative, not secure authorization. No rule is written to the backend or activated by approval.
          </p>
        </section>
      </>
    )
  }

  const renderReports = () => {
    const dateKey = value => {
      if (!value) return ''
      const date = new Date(value)
      if (Number.isNaN(date.getTime())) return ''
      return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`
    }

    const useCaseOf = alert =>
      alert.rule_description || `Wazuh rule ${alert.rule_id || 'Unclassified'}`

    const useCases = [...new Set(alerts.map(useCaseOf))].sort()

    const filteredAlerts = alerts.filter(alert => {
      const date = dateKey(alert.timestamp)
      const dateMatches =
        (!reportStartDate || date >= reportStartDate) &&
        (!reportEndDate || date <= reportEndDate)
      const useCaseMatches =
        reportUseCase === 'All' || useCaseOf(alert) === reportUseCase
      return dateMatches && useCaseMatches
    })

    const filteredInvestigations = filteredAlerts
      .map(alert => investigationForAlert(alert))
      .filter(Boolean)

    const filteredIncidents = incidents.filter(incident => {
      const date = dateKey(incident.created_at)
      return (!reportStartDate || date >= reportStartDate) &&
        (!reportEndDate || date <= reportEndDate)
    })

    const severityCounts = {
      Critical: filteredAlerts.filter(item => Number(item.rule_level) >= 12).length,
      High: filteredAlerts.filter(item => Number(item.rule_level) >= 8 && Number(item.rule_level) < 12).length,
      Medium: filteredAlerts.filter(item => Number(item.rule_level) >= 5 && Number(item.rule_level) < 8).length,
      Low: filteredAlerts.filter(item => Number(item.rule_level) < 5).length,
    }

    const decisionCounts = {
      'True Positive': filteredInvestigations.filter(item => item.decision === 'True Positive').length,
      'False Positive': filteredInvestigations.filter(item => item.decision === 'False Positive').length,
      'Uncertain / other': filteredInvestigations.filter(item => !['True Positive', 'False Positive'].includes(item.decision)).length,
    }

    const selectedYear = Number((reportStartDate || reportEndDate || new Date().toISOString()).slice(0, 4))
    const monthLabels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    const monthlyData = monthLabels.map((label, month) => ({
      label,
      value: filteredAlerts.filter(item => {
        const date = new Date(item.timestamp)
        return !Number.isNaN(date.getTime()) &&
          date.getFullYear() === selectedYear &&
          date.getMonth() === month
      }).length,
    }))

    const quarterlyData = [0, 1, 2, 3].map(quarter => ({
      label: `Q${quarter + 1}`,
      value: filteredAlerts.filter(item => {
        const date = new Date(item.timestamp)
        return !Number.isNaN(date.getTime()) &&
          date.getFullYear() === selectedYear &&
          Math.floor(date.getMonth() / 3) === quarter
      }).length,
    }))

    const firstYear = Math.max(2000, selectedYear - 4)
    const yearlyData = Array.from({ length: 5 }, (_, index) => firstYear + index)
      .map(year => ({
        label: String(year),
        value: filteredAlerts.filter(item => {
          const date = new Date(item.timestamp)
          return !Number.isNaN(date.getTime()) && date.getFullYear() === year
        }).length,
      }))

    const renderTrendChart = (title, subtitle, data) => {
      const maximum = Math.max(1, ...data.map(item => item.value))
      return (
        <section className="report-chart-card">
          <div className="report-chart-heading">
            <h3>{title}</h3>
            <span>{subtitle}</span>
          </div>
          <div className="report-chart-bars" role="img" aria-label={`${title}: ${data.map(item => `${item.label} ${item.value}`).join(', ')}`}>
            {data.map(item => (
              <div className="report-chart-column" key={item.label}>
                <strong>{item.value}</strong>
                <div className="report-chart-track">
                  <div
                    className="report-chart-bar"
                    style={{ height: `${Math.max(item.value > 0 ? 5 : 0, (item.value / maximum) * 100)}%` }}
                  />
                </div>
                <span>{item.label}</span>
              </div>
            ))}
          </div>
          <p className="report-chart-foot">Alert records currently loaded in this dashboard</p>
        </section>
      )
    }

    const downloadReport = () => {
      const rows = [
        ['SOC AGENT SECURITY REPORT'],
        ['Generated at', new Date().toLocaleString()],
        ['Date from', reportStartDate || 'Any'],
        ['Date to', reportEndDate || 'Any'],
        ['Use case', reportUseCase],
        ['Data scope', `Filtered from ${alerts.length} alerts currently loaded by the dashboard`],
        ['Filtered alerts', filteredAlerts.length],
        ['Filtered incidents loaded', filteredIncidents.length],
        ['Matched investigations loaded', filteredInvestigations.length],
        [],
        ['Alert ID', 'Wazuh Alert ID', 'Timestamp', 'Rule ID', 'Use Case', 'Rule Level', 'Severity', 'Source IP', 'Destination IP', 'Username', 'Agent', 'MITRE ATT&CK', 'Investigation Decision', 'Investigation Severity', 'Investigation Status'],
        ...filteredAlerts.map(alert => {
          const investigation = investigationForAlert(alert)
          const level = Number(alert.rule_level) || 0
          const severity = level >= 12 ? 'Critical' : level >= 8 ? 'High' : level >= 5 ? 'Medium' : 'Low'
          return [
            alert.id,
            alert.wazuh_alert_id,
            alert.timestamp,
            alert.rule_id,
            useCaseOf(alert),
            alert.rule_level,
            severity,
            alert.source_ip,
            alert.destination_ip,
            alert.username,
            alert.agent_name,
            typeof alert.mitre_attack === 'object' ? JSON.stringify(alert.mitre_attack) : alert.mitre_attack,
            investigation?.decision || 'Not investigated',
            investigation?.severity || '',
            investigation?.investigation_status || '',
          ]
        }),
      ]

      const csv = rows.map(row => row.map(value => {
        const text = value === null || value === undefined ? '' : String(value)
        return `"${text.replace(/"/g, '""')}"`
      }).join(',')).join('\r\n')

      const blob = new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8;' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `SOC_Security_Report_${reportStartDate || 'start'}_to_${reportEndDate || 'end'}.csv`
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      URL.revokeObjectURL(url)
      setNotice(`CSV report generated with ${filteredAlerts.length} filtered alert records. Export scope is limited to records currently loaded by the dashboard.`)
    }

    return (
      <>
        <section className="stats report-kpis">
          <article className="stat-card c-red"><div className="stat-body"><span className="stat-val">{filteredAlerts.length}</span><span className="stat-lbl">Filtered alerts · loaded records</span></div></article>
          <article className="stat-card c-green"><div className="stat-body"><span className="stat-val">{severityCounts.Critical}</span><span className="stat-lbl">Critical alerts · filtered</span></div></article>
          <article className="stat-card c-orange"><div className="stat-body"><span className="stat-val">{filteredIncidents.length}</span><span className="stat-lbl">Incidents · loaded and filtered</span></div></article>
          <article className="stat-card c-cyan"><div className="stat-body"><span className="stat-val">{filteredInvestigations.length}</span><span className="stat-lbl">Matched investigations · loaded</span></div></article>
        </section>

        <section className="card report-filter-card">
          <div className="card-head">
            <div>
              <h3>Report Builder</h3>
              <p className="alert-meta">Filter the available SOC records and generate a downloadable report.</p>
            </div>
            <span className="tag approved">Interactive</span>
          </div>
          <div className="report-filter-grid">
            <label>
              <span>From date</span>
              <input className="report-filter-control" type="date" value={reportStartDate} max={reportEndDate || undefined} onChange={event => setReportStartDate(event.target.value)} />
            </label>
            <label>
              <span>To date</span>
              <input className="report-filter-control" type="date" value={reportEndDate} min={reportStartDate || undefined} onChange={event => setReportEndDate(event.target.value)} />
            </label>
            <label>
              <span>Use case / detection rule</span>
              <select className="report-filter-control" value={reportUseCase} onChange={event => setReportUseCase(event.target.value)}>
                <option value="All">All use cases</option>
                {useCases.map(useCase => <option key={useCase} value={useCase}>{useCase}</option>)}
              </select>
            </label>
            <div className="report-filter-actions">
              <button className="btn" type="button" onClick={() => {
                setReportStartDate(`${new Date().getFullYear()}-01-01`)
                setReportEndDate(new Date().toISOString().slice(0, 10))
                setReportUseCase('All')
              }}>Reset filters</button>
              <button className="btn btn-primary" type="button" onClick={downloadReport}>Generate &amp; Download CSV</button>
            </div>
          </div>
          <p className="alert-meta">The filters apply to the records currently loaded in the browser. They do not yet query the entire database for historical records.</p>
        </section>

        <section className="report-chart-grid">
          {renderTrendChart('Monthly activity', `12 months · ${selectedYear}`, monthlyData)}
          {renderTrendChart('Quarterly activity', `Four quarters · ${selectedYear}`, quarterlyData)}
          {renderTrendChart('Yearly activity', 'Five-year view', yearlyData)}
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Alert severity distribution</h3>
              <p className="alert-meta">Based on filtered alert records.</p>
            </div>
            <span className="pill">{filteredAlerts.length} alerts</span>
          </div>
          <div className="report-breakdown-grid">
            {Object.entries(severityCounts).map(([label, count]) => (
              <div className="report-breakdown-item" key={label}>
                <span>{label}</span><strong>{count}</strong>
                <div className="report-breakdown-track"><div style={{ width: `${filteredAlerts.length ? (count / filteredAlerts.length) * 100 : 0}%` }} /></div>
              </div>
            ))}
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Investigation outcomes</h3>
              <p className="alert-meta">Only investigations matched to the filtered alert records are counted here.</p>
            </div>
            <span className="pill">{filteredInvestigations.length} matched</span>
          </div>
          <div className="report-breakdown-grid">
            {Object.entries(decisionCounts).map(([label, count]) => (
              <div className="report-breakdown-item" key={label}>
                <span>{label}</span><strong>{count}</strong>
                <div className="report-breakdown-track"><div style={{ width: `${filteredInvestigations.length ? (count / filteredInvestigations.length) * 100 : 0}%` }} /></div>
              </div>
            ))}
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>Metric</th><th>Count</th><th>Data scope</th></tr></thead>
              <tbody>
                <tr><td>Total alerts</td><td>{displayValue(summary?.total_alerts)}</td><td>Complete backend count</td></tr>
                <tr><td>Critical alerts</td><td>{displayValue(summary?.critical_alerts)}</td><td>Complete backend count</td></tr>
                <tr><td>Total investigations</td><td>{displayValue(summary?.total_investigations)}</td><td>Complete backend count</td></tr>
                <tr><td>Pending human review</td><td>{displayValue(summary?.pending_review)}</td><td>Complete backend summary</td></tr>
                <tr><td>Open incidents</td><td>{displayValue(summary?.open_incidents)}</td><td>Complete backend summary</td></tr>
                <tr><td>Filtered alerts</td><td>{filteredAlerts.length}</td><td>Loaded records after filters</td></tr>
                <tr><td>Filtered incidents</td><td>{filteredIncidents.length}</td><td>Loaded records after filters</td></tr>
                <tr><td>Matched investigations</td><td>{filteredInvestigations.length}</td><td>Loaded records matched to filtered alerts</td></tr>
              </tbody>
            </table>
          </div>
        </section>

        <section className="card">
          <div className="card-head">
            <div>
              <h3>Filtered alert records</h3>
              <p className="alert-meta">Preview of the records included in the CSV export.</p>
            </div>
            <span className="pill">{filteredAlerts.length} records</span>
          </div>
          {filteredAlerts.length === 0 ? (
            <p>No loaded alerts match the selected filters.</p>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead><tr><th>Timestamp</th><th>Use case</th><th>Severity</th><th>Source IP</th><th>Investigation</th></tr></thead>
                <tbody>
                  {filteredAlerts.slice(0, 50).map(alert => {
                    const level = Number(alert.rule_level) || 0
                    const severity = level >= 12 ? 'Critical' : level >= 8 ? 'High' : level >= 5 ? 'Medium' : 'Low'
                    return (
                      <tr key={alert.id}>
                        <td>{formatAlertTime(alert.timestamp)}</td>
                        <td>{useCaseOf(alert)}</td>
                        <td>{severity}</td>
                        <td>{displayValue(alert.source_ip)}</td>
                        <td>{investigationForAlert(alert)?.decision || 'Not investigated'}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {filteredAlerts.length > 50 && <p className="alert-meta">Showing the first 50 records. The CSV export includes all {filteredAlerts.length} filtered records currently loaded.</p>}
            </div>
          )}
        </section>

        <section className="card report-integrity-note">
          <strong>Reporting coverage and accuracy</strong>
          <p>Backend-wide totals above come from database aggregation. The charts, filters, severity distribution, outcome breakdown and CSV detail rows use the records currently loaded by this frontend (up to 200 alerts, 100 incidents and 100 investigations). Historical reporting across the full database requires a backend reporting API with date-range aggregation and pagination.</p>
          <button className="btn" type="button" onClick={() => { loadDashboard(); loadActions() }} disabled={dashboardLoading || loading}>Refresh report data</button>
        </section>
      </>
    )
  }

  const renderSettings = () => (
    <section className="card">
      <div className="card-head"><h3>Application Configuration</h3><span className="tag approved">Read-only status</span></div>
      <div className="table-wrap"><table className="data-table">
        <thead><tr><th>Component</th><th>Current evidence/status</th></tr></thead>
        <tbody>
          <tr><td>Frontend</td><td>React application served through the frontend container</td></tr>
          <tr><td>Backend</td><td>{dashboardError ? 'API request error' : dashboardLoading ? 'Checking API' : 'Dashboard APIs responding'}</td></tr>
          <tr><td>Database</td><td>{dashboardError ? 'Data retrieval failed or unavailable' : 'PostgreSQL-backed records returned by API'}</td></tr>
          <tr><td>Wazuh integration</td><td>Webhook-based alert ingestion; API authentication previously verified</td></tr>
          <tr><td>Reviewer identity</td><td>{reviewer || 'Not returned by response-actions API'}</td></tr>
          <tr><td>Response execution</td><td>Human-gated simulated actions only</td></tr>
          <tr><td>Alert records loaded</td><td>{alerts.length}</td></tr>
          <tr><td>Incident records loaded</td><td>{incidents.length}</td></tr>
          <tr><td>Investigation records loaded</td><td>{investigations.length}</td></tr>
        </tbody>
      </table></div>
      <p className="alert-meta">This page is informational. Credentials, passwords, API tokens and environment-variable values are intentionally never displayed.</p>
      <button className="btn" onClick={() => { loadDashboard(); loadActions() }} disabled={dashboardLoading || loading}>Refresh application status</button>
    </section>
  )

  const pageRenderers = {
    dashboard: renderDashboard,
    alerts: renderAlerts,
    incidents: renderIncidents,
    investigations: renderInvestigations,
    agents: renderAgents,
    playbooks: renderPlaybooks,
    reports: renderReports,
    settings: renderSettings,
  }

  return (
    <div className="app">
      <header className="site-header">
        <div className="brand">
          <span className="brand-text">SOC<strong>Agent</strong></span>
        </div>
        <nav className="nav" aria-label="Primary navigation">
          {navItems.map(item => (
            <button
              key={item.id}
              className={`nav-btn${nav === item.id ? ' active' : ''}`}
              onClick={() => setNav(item.id)}
              aria-current={nav === item.id ? 'page' : undefined}
            >
              {item.label}
            </button>
          ))}
        </nav>
        <div className="header-actions">
          <div className="header-status"><span className="header-online-dot" />Dashboard Online</div>
          <button
            type="button"
            className={`settings-icon-btn${nav === 'settings' ? ' active' : ''}`}
            onClick={() => setNav('settings')}
            title="Settings"
            aria-label="Open settings"
            aria-current={nav === 'settings' ? 'page' : undefined}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M12 8.2a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0-7.6Z" />
              <path d="m19.4 13.5 1.1.9-1.5 2.6-1.4-.5a7.8 7.8 0 0 1-1.7 1l-.2 1.5h-3l-.3-1.5a7.8 7.8 0 0 1-1.7-1l-1.4.5-1.5-2.6 1.1-.9a7.4 7.4 0 0 1 0-2l-1.1-.9 1.5-2.6 1.4.5a7.8 7.8 0 0 1 1.7-1l.3-1.5h3l.2 1.5a7.8 7.8 0 0 1 1.7 1l1.4-.5 1.5 2.6-1.1.9a7.4 7.4 0 0 1 0 2Z" />
            </svg>
          </button>
        </div>
      </header>

      <main className="main">
        <header className="topbar">
          <div>
            <h2 className="page-title">{pageTitle}</h2>
            <p className="page-sub">{pageSubtitle}</p>
          </div>
          <span className="live"><span className="pulse" /> LIVE</span>
        </header>

        {error && (
          <div role="alert" className="card" style={{ marginBottom: 16 }}>
            <strong>API error:</strong> {error}
            <button className="btn" onClick={loadActions} style={{ marginLeft: 12 }}>Retry</button>
          </div>
        )}
        {notice && (
          <div role="status" className="card" style={{ marginBottom: 16 }}>
            {notice}
            <button className="btn" onClick={() => setNotice('')} style={{ marginLeft: 12 }}>Dismiss</button>
          </div>
        )}
        {pageRenderers[nav] ? pageRenderers[nav]() : renderDashboard()}

        {selectedAlert && (() => {
          const alert = selectedAlert
          const investigation = investigationForAlert(alert)
          const review = localReviews[alert.id]
          const severity = severityForAlert(alert.rule_level)
          const mitre = alert.mitre_attack
          const mitreItems = Array.isArray(mitre)
            ? mitre
            : mitre && typeof mitre === 'object'
              ? Object.entries(mitre).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : String(value)}`)
              : mitre ? [String(mitre)] : []

          return (
            <div
              className="alert-modal-backdrop"
              onClick={event => {
                if (event.target === event.currentTarget) setSelectedAlert(null)
              }}
            >
              <section
                className="alert-detail-modal"
                role="dialog"
                aria-modal="true"
                aria-labelledby="alert-detail-heading"
              >
                <header className="alert-detail-header">
                  <div>
                    <span className="alert-detail-eyebrow">SOC ANALYST · ALERT INVESTIGATION</span>
                    <h2 id="alert-detail-heading">
                      {alert.rule_description || `Wazuh Alert ${alert.wazuh_alert_id || alert.id}`}
                    </h2>
                    <p>Alert database ID #{alert.id} · Wazuh ID {displayValue(alert.wazuh_alert_id)}</p>
                  </div>
                  <button
                    type="button"
                    className="alert-modal-close"
                    onClick={() => setSelectedAlert(null)}
                    aria-label="Close alert details"
                  >×</button>
                </header>

                <div className="alert-detail-content">
                  <div className="alert-detail-summary">
                    <span className={`tag ${severity}`}>{severity.toUpperCase()}</span>
                    <span className="tag pending">Rule level {displayValue(alert.rule_level)}</span>
                    <span className="tag">{investigation?.decision || 'Not investigated'}</span>
                    {investigation?.human_review_required && (
                      <span className="tag pending">Human review required</span>
                    )}
                  </div>

                  <section className="alert-detail-section">
                    <h3>Analyst summary</h3>
                    <p>
                      {alert.rule_description
                        ? `Wazuh generated this alert because the detection rule "${alert.rule_description}" matched the observed activity.`
                        : 'The alert does not contain a rule description. Review the available event metadata before drawing a conclusion.'}
                    </p>
                    <p>
                      {investigation
                        ? `The recorded investigation decision is ${investigation.decision || 'Uncertain'}, with severity ${investigation.severity || 'not specified'} and status ${investigation.investigation_status || 'not specified'}.`
                        : 'No matching investigation record was returned by the current backend API.'}
                    </p>
                    <p className="alert-detail-disclaimer">
                      This summary is generated from persisted alert metadata and investigation status. It is not a new AI analysis.
                    </p>
                  </section>

                  <section className="alert-detail-section">
                    <h3>Event and asset information</h3>
                    <div className="alert-detail-grid">
                      <div><label>Event timestamp</label><strong>{formatAlertTime(alert.timestamp)}</strong></div>
                      <div><label>Wazuh rule ID</label><strong>{displayValue(alert.rule_id)}</strong></div>
                      <div><label>Source IP</label><strong>{displayValue(alert.source_ip)}</strong></div>
                      <div><label>Destination IP</label><strong>{displayValue(alert.destination_ip)}</strong></div>
                      <div><label>Username</label><strong>{displayValue(alert.username)}</strong></div>
                      <div><label>Agent name</label><strong>{displayValue(alert.agent_name)}</strong></div>
                      <div><label>Agent ID</label><strong>{displayValue(alert.agent_id)}</strong></div>
                      <div><label>Decoder</label><strong>{displayValue(alert.decoder)}</strong></div>
                    </div>
                  </section>

                  <section className="alert-detail-section">
                    <h3>Investigation assessment</h3>
                    {investigation ? (
                      <div className="alert-detail-grid">
                        <div><label>Decision</label><strong>{displayValue(investigation.decision)}</strong></div>
                        <div><label>AI severity</label><strong>{displayValue(investigation.severity)}</strong></div>
                        <div><label>Investigation ID</label><strong>{displayValue(investigation.id)}</strong></div>
                        <div><label>Investigation status</label><strong>{displayValue(investigation.investigation_status)}</strong></div>
                        <div><label>Confidence</label><strong>{displayValue(investigation.confidence)}</strong></div>
                        <div><label>Completed at</label><strong>{formatAlertTime(investigation.completed_at)}</strong></div>
                      </div>
                    ) : (
                      <p>No investigation assessment is available for this alert.</p>
                    )}
                    {investigation?.error && (
                      <p className="alert-detail-warning">Investigation error: {investigation.error}</p>
                    )}
                  </section>

                  <section className="alert-detail-section">
                    <h3>MITRE ATT&CK mapping</h3>
                    {mitreItems.length ? (
                      <ul>{mitreItems.map((item, index) => <li key={index}>{item}</li>)}</ul>
                    ) : (
                      <p>No MITRE ATT&CK mapping was returned for this alert.</p>
                    )}
                  </section>

                  <section className="alert-detail-section">
                    <h3>Human review</h3>
                    {review ? (
                      <div className="alert-review-result">
                        <strong>{review.decision} · Local demo decision</strong>
                        <p>Reviewer: {review.reviewer}</p>
                        <p>Time: {formatAlertTime(review.timestamp)}</p>
                        <p>Comment: {review.reason}</p>
                      </div>
                    ) : (
                      <>
                        <p>This alert is awaiting your local review decision.</p>
                        <div className="alert-detail-actions">
                          <button
                            type="button"
                            className="btn ok"
                            onClick={() => {
                              if (!window.confirm('Approve this alert for the demo review record?')) return
                              setLocalReviews(previous => ({
                                ...previous,
                                [alert.id]: {
                                  decision: 'Approved',
                                  reviewer: reviewer || 'Local reviewer',
                                  timestamp: new Date().toISOString(),
                                  reason: 'Approved in frontend demo review',
                                },
                              }))
                            }}
                          >Approve alert</button>
                          <button
                            type="button"
                            className="btn no"
                            onClick={() => {
                              const reason = window.prompt('Enter a reason for denying this alert:')
                              if (reason === null) return
                              if (reason.trim().length < 3) {
                                setError('Please enter a denial reason of at least 3 characters.')
                                return
                              }
                              setLocalReviews(previous => ({
                                ...previous,
                                [alert.id]: {
                                  decision: 'Denied',
                                  reviewer: reviewer || 'Local reviewer',
                                  timestamp: new Date().toISOString(),
                                  reason: reason.trim(),
                                },
                              }))
                            }}
                          >Deny alert</button>
                        </div>
                      </>
                    )}
                    <p className="alert-detail-disclaimer">
                      Demo mode: this decision is held in frontend memory only. It is not persisted to the backend and does not execute a response action.
                    </p>
                  </section>
                </div>

                <footer className="alert-detail-footer">
                  <button type="button" className="btn" onClick={() => setSelectedAlert(null)}>Close details</button>
                </footer>
              </section>
            </div>
          )
        })()}
      </main>
    </div>
  )
}

export default App
