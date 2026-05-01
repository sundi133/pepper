  const sast = getSastEngineMeta(finding);
  const llmCwe =
    typeof sast?.llmCweId === "string"
      ? sast.llmCweId
      : typeof sast?.llmCwe === "string"
        ? sast.llmCwe
        : null;
  const filePathOnly = report?.affectedFilePath || finding.filePath || "";
  const lineNum = finding.startLine ?? report?.exactLineNumber ?? null;
  const displayCode = vulnCode
    ? formatCodeBlockWithLineNumbers(
        vulnCode,
        finding.startLine ?? report?.exactLineNumber,
      )
    : "";
  const whyBullets = buildWhyVulnerableBullets(finding, report);

  return (
    <div className="sast-report finding-report report-container max-w-full min-w-0 overflow-x-hidden p-1 sm:p-0">
      {/* 1. Finding header card */}
      <div className="finding-card report-container">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="min-w-0 flex-1 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <span className="text-xs font-bold uppercase tracking-wide text-muted-foreground">
                {formatSeverityLabel(finding.severity)}
              </span>
            </div>
            <h2 className="text-balance break-words text-xl font-bold leading-tight text-foreground sm:text-2xl">
              {displayTitle}
            </h2>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <div className="min-w-0">
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Status
                </p>
                <div className="mt-1">
                  <Select
                    value={finding.status || "OPEN"}
                    onValueChange={handleStatusChange}
                  >
                    <SelectTrigger className="h-9 w-full max-w-[220px] text-xs">
                      <SelectValue placeholder={statusLabel} />
                    </SelectTrigger>
                    <SelectContent>
                      {FINDING_STATUSES.map((s) => (
                        <SelectItem key={s.value} value={s.value}>
                          <span
                            className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${s.color}`}
                          >
                            {s.label}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Confidence
                </p>
                <p className="report-paragraph mt-1 text-sm font-semibold tabular-nums">
                  {confidencePercent !== null ? `${confidencePercent}%` : "—"}
                </p>
              </div>
              <div className="min-w-0 sm:col-span-1">
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  CWE / LLM-CWE
                </p>
                <div className="report-paragraph mt-1 flex flex-wrap items-center gap-2 text-sm">
                  {finding.cweId ? (
                    <a
                      href={getCweUrl(finding.cweId)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 break-all font-medium text-primary hover:underline"
                    >
                      {finding.cweId}
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                  {llmCwe && (
                    <>
                      <span className="text-muted-foreground">/</span>
                      <span className="break-all font-mono text-sm">{llmCwe}</span>
                    </>
                  )}
                </div>
              </div>
            </div>
            {locationLine && (
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  File / line
                </p>
                <p className="report-paragraph mt-1 font-mono text-sm text-foreground">
                  {locationLine}
                </p>
              </div>
            )}
            {report?.affectedFunction && (
              <div>
                <p className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                  Function / component
                </p>
                <p className="report-paragraph mt-1 font-mono text-sm text-foreground">
                  {report.affectedFunction}
                </p>
              </div>
            )}
            <div className="flex flex-wrap gap-2">
              {finding.ruleId && (
                <Badge variant="secondary" className="max-w-full font-mono text-xs">
                  {finding.ruleId}
                </Badge>
              )}
              <Badge variant="outline" className="text-xs">
                {SCANNER_LABELS[
                  finding.scanner as keyof typeof SCANNER_LABELS
                ] || finding.scanner}
              </Badge>
            </div>
          </div>
          {onCollapse && (
            <Button
              variant="outline"
              size="sm"
              className="shrink-0 gap-1.5"
              onClick={(e) => {
                e.stopPropagation();
                onCollapse();
              }}
            >
              <ChevronUp className="h-4 w-4" aria-hidden />
              Collapse
            </Button>
          )}
        </div>
      </div>

      <div className="report-container mt-4 max-h-[min(88vh,1800px)] space-y-5 overflow-x-hidden overflow-y-auto overscroll-contain pb-4">
        {/* 2. Location */}
        {(filePathOnly || displayCode) && (
          <ReportSection title="Location" icon={FileCode}>
            {filePathOnly && (
              <p className="report-paragraph description text-sm text-foreground">
                <span className="font-semibold text-muted-foreground">File: </span>
                <span className="break-all font-mono">{filePathOnly}</span>
              </p>
            )}
            {lineNum != null && (
              <p className="report-paragraph description mt-2 text-sm">
                <span className="font-semibold text-muted-foreground">Line: </span>
                {lineNum}
                {finding.endLine != null &&
                finding.startLine != null &&
                finding.endLine !== finding.startLine
                  ? `–${finding.endLine}`
                  : ""}
              </p>
            )}
            {report?.affectedFunction && (
              <p className="report-paragraph description mt-2 text-sm">
                <span className="font-semibold text-muted-foreground">
                  Function / component:{" "}
                </span>
                <span className="break-all font-mono text-foreground">
                  {report.affectedFunction}
                </span>
              </p>
            )}
            {displayCode ? (
              <div className="mt-4">
                <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Vulnerable code (with line numbers)
                </p>
                <FindingReportCodeBlock code={displayCode} />
              </div>
            ) : null}
          </ReportSection>
        )}

        {/* 3. Description */}
        <ReportSection title="Description" icon={Info}>
          <p className="report-paragraph description text-sm text-muted-foreground">
            {mainDescription}
          </p>
        </ReportSection>

        {report ? (
          <>
            {/* 4. Why this is vulnerable */}
            {whyBullets.length > 0 && (
              <ReportSection title="Why this is vulnerable" icon={AlertTriangle}>
                <ul className="list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                  {whyBullets.map((b, i) => (
                    <li key={i} className="report-paragraph">
                      {b}
                    </li>
                  ))}
                </ul>
              </ReportSection>
            )}

            {/* 5. Attack reasoning */}
            {(report.realWorldAttackScenario ||
              report.advancedAttackerReasoning ||
              report.attackPreconditions) && (
              <ReportSection title="Attack reasoning" icon={Target}>
                <div className="attack-reasoning space-y-4">
                  {report.realWorldAttackScenario && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Real-world attack scenario
                      </h4>
                      <p className="report-paragraph text-sm text-muted-foreground">
                        {report.realWorldAttackScenario}
                      </p>
                    </div>
                  )}
                  {report.advancedAttackerReasoning && (
                    <div>
                      <h4 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                        Advanced attack chain
                      </h4>
                      <p className="report-paragraph text-sm text-muted-foreground">
                        {report.advancedAttackerReasoning}
                      </p>
                    </div>
                  )}
                  {report.attackPreconditions &&
                    Object.keys(report.attackPreconditions).length > 0 && (
                      <dl className="space-y-2 border-t border-border/60 pt-3 text-sm">
                        {Object.entries(report.attackPreconditions).map(
                          ([key, value]) => (
                            <div key={key} className="grid gap-1 sm:grid-cols-[minmax(0,200px)_1fr]">
                              <dt className="font-semibold text-foreground">
                                {formatPreconditionLabel(key)}:
                              </dt>
                              <dd className="report-paragraph min-w-0 text-muted-foreground">
                                {value}
                              </dd>
                            </div>
                          ),
                        )}
                      </dl>
                    )}
                </div>
              </ReportSection>
            )}

            {/* 6. Steps to reproduce */}
            {(report.stepsToReproduce?.length ||
              report.proofOfConcept ||
              report.expectedVulnerableBehavior) && (
              <ReportSection title="Steps to reproduce" icon={Target}>
                {report.stepsToReproduce &&
                  report.stepsToReproduce.length > 0 && (
                    <ol className="report-steps mb-4 list-decimal space-y-3 pl-5 text-sm text-muted-foreground">
                      {report.stepsToReproduce.map((step, index) => (
                        <li key={index} className="report-paragraph pl-1">
                          {step}
                        </li>
                      ))}
                    </ol>
                  )}
                {report.proofOfConcept && (
                  <div>
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Commands / payload (authorized testing)
                    </p>
                    <FindingReportCodeBlock code={report.proofOfConcept} />
                  </div>
                )}
                {report.expectedVulnerableBehavior && (
                  <p className="report-paragraph mt-3 text-xs text-muted-foreground">
                    <span className="font-semibold text-foreground">
                      Expected vulnerable behavior:{" "}
                    </span>
                    {report.expectedVulnerableBehavior}
                  </p>
                )}
              </ReportSection>
            )}

            {/* 7. Impact */}
            {report.businessImpact && (
              <ReportSection title="Impact" icon={AlertTriangle}>
                <p className="report-paragraph impact text-sm text-muted-foreground">
                  {report.businessImpact}
                </p>
              </ReportSection>
            )}

            {/* 8. How to fix */}
            {(report.secureFixExplanation || report.secureCodeExample) && (
              <ReportSection title="How to fix" icon={Wrench}>
                {report.secureFixExplanation && (
                  <div className="remediation space-y-3">
                    <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Immediate remediation &amp; secure design
                    </h4>
                    <p className="report-paragraph remediation text-sm text-muted-foreground">
                      {report.secureFixExplanation}
                    </p>
                  </div>
                )}
                {report.secureCodeExample && (
                  <div className="mt-4">
                    <p className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      Secure code example
                    </p>
                    <FindingReportCodeBlock code={report.secureCodeExample} />
                  </div>
                )}
              </ReportSection>
            )}

            {/* 9. Security tests */}
            {report.securityTests && (
              <ReportSection title="Security tests" icon={Shield}>
                {renderSecurityTestsContent(report.securityTests)}
              </ReportSection>
            )}

            {/* 10. Regression prevention */}
            {report.regressionPrevention && (
              <ReportSection title="Regression prevention" icon={Info}>
                <p className="report-paragraph regression-prevention text-sm text-muted-foreground">
                  {report.regressionPrevention}
                </p>
              </ReportSection>
            )}
          </>
        ) : null}

        {/* 11. Attack kill chain */}
        <ReportSection title="Attack kill chain" icon={Target}>
          <div className="kill-chain">
            {killChain.map((step, i) => (
              <div
                key={step.phase}
                className={
                  step.active
                    ? "kill-chain-step kill-chain-step-active"
                    : "kill-chain-step"
                }
              >
                <div
                  className={
                    step.active
                      ? "kill-chain-number"
                      : "kill-chain-number kill-chain-number-muted"
                  }
                >
                  {i + 1}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="font-semibold text-foreground">{step.phase}</div>
                  {step.active && (
                    <p className="report-paragraph mt-1 text-sm text-muted-foreground">
                      {step.description}
                    </p>
                  )}
                </div>
                {step.active && (
                  <Zap className="mt-0.5 h-4 w-4 shrink-0 text-red-500" aria-hidden />
                )}
              </div>
            ))}
          </div>
        </ReportSection>

        {remediations.length > 0 && (
          <ReportSection title="Suggested remediation" icon={Wrench}>
            <div className="space-y-2">
              {remediations.map((rem, i) => {
                const priorityColor =
                  rem.priority === "Immediate"
                    ? "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300"
                    : rem.priority === "Short-term"
                      ? "border-yellow-200 bg-yellow-50 text-yellow-900 dark:border-yellow-900 dark:bg-yellow-950/40 dark:text-yellow-200"
                      : "border-blue-200 bg-blue-50 text-blue-900 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-200";
                return (
                  <div
                    key={i}
                    className="flex flex-col gap-2 rounded-lg border p-3 sm:flex-row sm:items-start"
                  >
                    <Badge
                      variant="outline"
                      className={`w-fit shrink-0 text-[10px] ${priorityColor}`}
                    >
                      {rem.priority}
                    </Badge>
                    <span className="report-paragraph min-w-0 flex-1 text-sm leading-relaxed text-muted-foreground">
                      {rem.action}
                    </span>
                  </div>
                );
              })}
            </div>
          </ReportSection>
        )}

        {embeddedRecommendation && remediations.length === 0 && (
          <ReportSection title="Recommendation" icon={Wrench}>
            <p className="report-paragraph rounded-lg border border-green-200 bg-green-50 p-3 text-sm leading-relaxed text-muted-foreground dark:border-green-900 dark:bg-green-950/30">
              {embeddedRecommendation}
            </p>
          </ReportSection>
        )}

        {finding.metadata &&
          Object.keys(finding.metadata).filter((k) => k !== "report").length >
            0 && (
          <ReportSection title="Additional details" icon={AlertTriangle}>
            <div className="rounded-lg border bg-muted/40 p-3">
              {Object.entries(finding.metadata)
                .filter(([key]) => key !== "report")
                .map(([key, value]) => (
                  <div
                    key={key}
                    className="report-paragraph border-b border-border/50 py-2 text-xs last:border-b-0"
                  >
                    <span className="font-semibold text-muted-foreground">
                      {key}:{" "}
                    </span>
                    <span className="break-all font-mono text-foreground">
                      {typeof value === "object"
                        ? JSON.stringify(value)
                        : String(value)}
                    </span>
                  </div>
                ))}
            </div>
          </ReportSection>
        )}
      </div>
    </div>
  );
