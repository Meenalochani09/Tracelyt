'use strict';
const fs = require('fs');
const path = require('path');
const { pool, query } = require('../config/database');
const { HttpError, isUuid } = require('../middleware/errorHandler');
const { verifyImageSignature, uploadDir } = require('../middleware/uploadMiddleware');
const { extractFromEvidence, parseTimestamp } = require('../services/evidenceExtractor');
const { analyse } = require('../services/riskAnalyzer');
const { buildRelationships, buildTimeline } = require('../services/relationshipBuilder');

const EVIDENCE_TYPES = ['sms', 'whatsapp', 'url', 'upi', 'screenshot', 'note'];
const MAX_TEXT = 20000;

const needId = (v, label = 'id') => { if (!isUuid(v)) throw new HttpError(400, `Invalid ${label}.`); return v; };
const clean = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

async function getInvestigationOr404(id) {
  const { rows } = await query('SELECT * FROM investigations WHERE id = $1', [needId(id)]);
  if (!rows[0]) throw new HttpError(404, 'Investigation not found.');
  return rows[0];
}

// ---------- Investigations ----------
exports.createInvestigation = async (req, res) => {
  const name = clean(req.body.case_name, 200);
  if (!name) throw new HttpError(400, 'case_name is required.');
  const { rows } = await query(
    `INSERT INTO investigations (case_name, case_description, scam_category, analysis_mode)
     VALUES ($1,$2,$3,'real') RETURNING *`,
    [name, clean(req.body.case_description, 5000) || null, clean(req.body.scam_category, 100) || null]);
  res.status(201).json({ ok: true, mode: 'real', data: rows[0] });
};

exports.listInvestigations = async (req, res) => {
  const { rows } = await query(
    `SELECT i.*, (SELECT count(*) FROM evidence e WHERE e.investigation_id = i.id)::int AS evidence_count,
            (SELECT count(*) FROM relationships r WHERE r.investigation_id = i.id)::int AS relationship_count
     FROM investigations i ORDER BY i.created_at DESC LIMIT 200`);
  const stats = {
    investigations: rows.length,
    evidence: rows.reduce((a, r) => a + r.evidence_count, 0),
    relationships: rows.reduce((a, r) => a + r.relationship_count, 0),
    high_concern: rows.filter((r) => r.risk_level === 'high_concern').length,
  };
  res.json({ ok: true, mode: 'real', data: rows, stats });
};

exports.getInvestigation = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  res.json({ ok: true, mode: 'real', data: inv });
};

exports.deleteInvestigation = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const client = await pool.connect();
  let storedFiles = [];

  try {
    await client.query('BEGIN');

    const files = await client.query(
      'SELECT storage_reference FROM evidence WHERE investigation_id=$1 AND storage_reference IS NOT NULL',
      [inv.id]
    );
    storedFiles = files.rows;

    // Remove dependent analysis rows before evidence and the investigation.
    await client.query('DELETE FROM relationships WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM investigation_events WHERE investigation_id=$1', [inv.id]);
    await client.query(
      `DELETE FROM extracted_entities
       WHERE evidence_id IN (SELECT id FROM evidence WHERE investigation_id=$1)`,
      [inv.id]
    );
    await client.query('DELETE FROM evidence WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM investigations WHERE id=$1', [inv.id]);

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }

  // Delete uploaded files only after the database transaction succeeds.
  storedFiles.forEach((row) => {
    if (row.storage_reference) removeFile(row.storage_reference);
  });

  res.json({
    ok: true,
    message: 'Investigation and associated records deleted successfully.',
    data: { deleted: inv.id },
  });
};

function removeFile(ref) {
  try { fs.unlinkSync(path.join(uploadDir, path.basename(ref))); } catch { /* already gone */ }
}

// Best-effort analysis after the evidence has already been saved. A failure here never loses the
// evidence: the person can still press Run Analysis, and the error is only logged.
async function tryAnalyse(inv) {
  try {
    const r = await runAnalysis(inv);
    return { entities: r.entities, relationships: r.relationships, events: r.events,
      risk_score: r.risk.risk_score, score_label: r.risk.score_label, risk_level: r.risk.risk_level, risk_label: r.risk.risk_label };
  } catch (e) { console.warn('Auto-analysis skipped:', e.message); return null; }
}

// ---------- Evidence ----------
exports.addEvidence = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const type = clean(req.body.evidence_type, 20).toLowerCase();
  if (!EVIDENCE_TYPES.includes(type)) { if (req.file) removeFile(req.file.filename); throw new HttpError(400, 'evidence_type must be one of: ' + EVIDENCE_TYPES.join(', ')); }

  let text = clean(req.body.original_text, MAX_TEXT) || null;
  let storageRef = null; let status = 'pending';

  if (req.file) {
    if (type !== 'screenshot') { removeFile(req.file.filename); throw new HttpError(400, 'Files can only be attached to screenshot evidence.'); }
    if (!verifyImageSignature(req.file.path)) { removeFile(req.file.filename); throw new HttpError(400, 'The file is not a valid image.'); }
    storageRef = req.file.filename;
    // OCR is not installed in this build. Text must be typed in, and the status says so honestly.
    if (!text) status = 'manual_entry_required';
  } else if (type === 'screenshot') {
    throw new HttpError(400, 'Attach an image file for screenshot evidence.');
  }
  if (!text && !storageRef) throw new HttpError(400, 'original_text is required.');

  let ts = null;
  if (req.body.incident_timestamp) {
    ts = parseTimestamp(req.body.incident_timestamp);
    if (!ts) { if (req.file) removeFile(req.file.filename); throw new HttpError(400, 'incident_timestamp is not a valid date/time.'); }
  }
  const { rows } = await query(
    `INSERT INTO evidence (investigation_id, evidence_type, original_text, storage_reference, source_identifier, incident_timestamp, processing_status)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [inv.id, type, text, storageRef, clean(req.body.source_identifier, 200) || null, ts, status]);
  const analysis = await tryAnalyse(inv);
  res.status(201).json({ ok: true, mode: 'real', data: rows[0], analysis,
    notice: status === 'manual_entry_required' ? 'Text could not be extracted from the image automatically. Please type the visible text into the evidence so it can be analysed.' : undefined });
};

exports.updateEvidenceText = async (req, res) => {
  const text = clean(req.body.original_text, MAX_TEXT);
  if (!text) throw new HttpError(400, 'original_text is required.');
  const { rows } = await query(
    `UPDATE evidence SET original_text=$2, processing_status='pending' WHERE id=$1 RETURNING *`, [needId(req.params.id), text]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  const analysis = await tryAnalyse({ id: rows[0].investigation_id });
  res.json({ ok: true, data: rows[0], analysis });
};

exports.listEvidence = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const params = [inv.id]; let where = 'investigation_id = $1';
  if (req.query.type) { params.push(String(req.query.type)); where += ` AND evidence_type = $${params.length}`; }
  if (req.query.q) { params.push('%' + String(req.query.q).slice(0, 100) + '%'); where += ` AND original_text ILIKE $${params.length}`; }
  const { rows } = await query(`SELECT * FROM evidence WHERE ${where} ORDER BY created_at ASC`, params);
  res.json({ ok: true, mode: 'real', data: rows });
};

exports.getEvidence = async (req, res) => {
  const { rows } = await query('SELECT * FROM evidence WHERE id=$1', [needId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  const ents = await query('SELECT * FROM extracted_entities WHERE evidence_id=$1 ORDER BY entity_type', [rows[0].id]);
  res.json({ ok: true, data: { ...rows[0], entities: ents.rows } });
};

exports.deleteEvidence = async (req, res) => {
  const { rows } = await query('DELETE FROM evidence WHERE id=$1 RETURNING id, storage_reference', [needId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Evidence not found.');
  if (rows[0].storage_reference) removeFile(rows[0].storage_reference);
  res.json({ ok: true, data: { deleted: rows[0].id } });
};

exports.getEvidenceFile = async (req, res) => {
  const { rows } = await query('SELECT storage_reference FROM evidence WHERE id=$1', [needId(req.params.id)]);
  if (!rows[0] || !rows[0].storage_reference) throw new HttpError(404, 'No file for this evidence.');
  const file = path.join(uploadDir, path.basename(rows[0].storage_reference));
  if (!fs.existsSync(file)) throw new HttpError(404, 'File no longer exists.');
  res.setHeader('Content-Disposition', 'inline');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.sendFile(file);
};

// ---------- Analysis ----------
async function loadCase(invId) {
  const evidence = (await query('SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY created_at', [invId])).rows;
  const entities = (await query(
    `SELECT x.* FROM extracted_entities x JOIN evidence e ON e.id = x.evidence_id WHERE e.investigation_id=$1`, [invId])).rows;
  return { evidence, entities };
}

// Multi-row INSERT in chunks. Returns the inserted rows when `returning` is true.
async function batchInsert(client, table, cols, rows, returning = false) {
  const out = [];
  const CHUNK = 500; // keeps well below PostgreSQL's 65,535-parameter limit
  for (let i = 0; i < rows.length; i += CHUNK) {
    const part = rows.slice(i, i + CHUNK);
    const params = []; 
    const values = part.map((row) => '(' + row.map((v) => { params.push(v); return '$' + params.length; }).join(',') + ')').join(',');
    const r = await client.query(`INSERT INTO ${table} (${cols.join(',')}) VALUES ${values}${returning ? ' RETURNING *' : ''}`, params);
    if (returning) out.push(...r.rows);
  }
  return out;
}

// Core analysis. Used by "Run Analysis" and automatically whenever evidence is saved or edited,
// so a case with a single piece of evidence always has entities, a rating and a score.
async function runAnalysis(inv) {
  const evidence = (await query('SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY created_at', [inv.id])).rows;
  if (!evidence.length) throw new HttpError(400, 'Add at least one piece of evidence before running analysis.');

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM relationships WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM investigation_events WHERE investigation_id=$1', [inv.id]);
    await client.query('DELETE FROM extracted_entities WHERE evidence_id = ANY($1::uuid[])', [evidence.map((e) => e.id)]);

    // Entities are extracted in memory first, then written with ONE multi-row INSERT per chunk
    // (instead of one round trip per entity to the remote database).
    const items = evidence.flatMap((ev) => extractFromEvidence(ev));
    const stored = await batchInsert(client, 'extracted_entities',
      ['evidence_id', 'entity_type', 'entity_value', 'normalized_value', 'extraction_method', 'confidence', 'explanation'],
      items.map((it) => [it.evidence_id, it.entity_type, it.entity_value, it.normalized_value, it.extraction_method, it.confidence, it.explanation]),
      true);
    const hasText = (ev) => !!(ev.original_text && ev.original_text.trim());
    const processedIds = evidence.filter(hasText).map((e) => e.id);
    const manualIds = evidence.filter((e) => !hasText(e)).map((e) => e.id);
    if (processedIds.length) await client.query(`UPDATE evidence SET processing_status='processed' WHERE id = ANY($1::uuid[])`, [processedIds]);
    if (manualIds.length) await client.query(`UPDATE evidence SET processing_status='manual_entry_required' WHERE id = ANY($1::uuid[])`, [manualIds]);

    const rels = buildRelationships(inv.id, evidence, stored);
    await batchInsert(client, 'relationships',
      ['investigation_id', 'source_entity_id', 'target_entity_id', 'relationship_type', 'explanation', 'supporting_evidence_id'],
      rels.map((r) => [r.investigation_id, r.source_entity_id, r.target_entity_id, r.relationship_type, r.explanation, r.supporting_evidence_id]));
    const events = buildTimeline(inv.id, evidence, stored);
    await batchInsert(client, 'investigation_events',
      ['investigation_id', 'evidence_id', 'event_description', 'event_timestamp', 'timestamp_known'],
      events.map((e) => [e.investigation_id, e.evidence_id, e.event_description, e.event_timestamp, e.timestamp_known]));
    const risk = analyse(evidence, stored);
    await client.query('UPDATE investigations SET risk_level=$2, updated_at=now() WHERE id=$1', [inv.id, risk.risk_level]);
    await client.query('COMMIT');
    return { investigation_id: inv.id, entities: stored.length, relationships: rels.length, events: events.length, risk };
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}

exports.analyse = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  res.json({ ok: true, mode: 'real', label: 'REAL ANALYSIS', data: await runAnalysis(inv) });
};

exports.getEntities = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { entities } = await loadCase(inv.id);
  res.json({ ok: true, mode: 'real', data: entities });
};

exports.getRisk = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { evidence, entities } = await loadCase(inv.id);
  res.json({ ok: true, mode: 'real', data: analyse(evidence, entities) });
};

// Risk score only (0-100) with its full breakdown. Same data as /risk, without the findings list.
exports.getScore = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { evidence, entities } = await loadCase(inv.id);
  const r = analyse(evidence, entities);
  res.json({ ok: true, mode: 'real', data: {
    risk_score: r.risk_score, score_band: r.score_band, score_label: r.score_label, score_max: r.score_max,
    risk_level: r.risk_level, risk_label: r.risk_label, score_breakdown: r.score_breakdown } });
};

// Graph payload for Cytoscape. Entities with the same type+value are merged into one node.
function buildGraph(evidence, entities, rels) {
  const evById = new Map(evidence.map((e) => [e.id, e]));
  const entById = new Map(entities.map((e) => [e.id, e]));
  const nodeKey = (e) => e.entity_type + '|' + e.normalized_value;

  const nodes = new Map();
  const touch = (e) => {
    const k = nodeKey(e);
    if (!nodes.has(k)) nodes.set(k, { id: k, label: e.entity_value, entity_type: e.entity_type, evidence_ids: new Set(), evidence_types: new Set(), explanations: [] });
    const n = nodes.get(k);
    n.evidence_ids.add(e.evidence_id);
    const ev = evById.get(e.evidence_id); if (ev) n.evidence_types.add(ev.evidence_type);
    if (e.explanation && !n.explanations.includes(e.explanation)) n.explanations.push(e.explanation);
  };
  const edges = [];
  for (const r of rels) {
    const a = entById.get(r.source_entity_id), b = entById.get(r.target_entity_id);
    if (!a || !b) continue;
    touch(a); touch(b);
    const s = nodeKey(a), t = nodeKey(b);
    if (s === t) continue; // same value in two evidence items is one node; the evidence list shows the link
    edges.push({ id: r.id, source: s, target: t, label: r.relationship_type.replace(/_/g, ' '), relationship_type: r.relationship_type,
      explanation: r.explanation, supporting_evidence_id: r.supporting_evidence_id });
  }
  return { nodes: [...nodes.values()].map((n) => ({ ...n, evidence_ids: [...n.evidence_ids], evidence_types: [...n.evidence_types] })), edges };
}

const TIMELINE_SQL = `SELECT ev.*, e.evidence_type, e.source_identifier FROM investigation_events ev
     LEFT JOIN evidence e ON e.id = ev.evidence_id
     WHERE ev.investigation_id=$1
     ORDER BY ev.timestamp_known DESC, ev.event_timestamp ASC, ev.created_at ASC`;
const withTimeLabel = (rows) => rows.map((r) => ({ ...r, timestamp_label: r.timestamp_known ? null : 'Unknown time' }));

exports.getRelationships = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const [{ evidence, entities }, rels] = await Promise.all([loadCase(inv.id), query('SELECT * FROM relationships WHERE investigation_id=$1', [inv.id])]);
  res.json({ ok: true, mode: 'real', label: 'REAL ANALYSIS', data: buildGraph(evidence, entities, rels.rows) });
};

exports.getTimeline = async (req, res) => {
  const inv = await getInvestigationOr404(req.params.id);
  const { rows } = await query(TIMELINE_SQL, [inv.id]);
  res.json({ ok: true, mode: 'real', data: withTimeLabel(rows) });
};

// Everything the workspace needs for one case, in a single request.
// Replaces 6 separate calls (case, evidence, entities, risk, graph, timeline) and the duplicated
// database reads each of them did. Five queries run in parallel; the result is identical.
exports.getBundle = async (req, res) => {
  const id = needId(req.params.id);
  const [inv, evidence, entities, rels, timeline] = await Promise.all([
    query('SELECT * FROM investigations WHERE id = $1', [id]),
    query('SELECT * FROM evidence WHERE investigation_id=$1 ORDER BY created_at', [id]),
    query('SELECT x.* FROM extracted_entities x JOIN evidence e ON e.id = x.evidence_id WHERE e.investigation_id=$1', [id]),
    query('SELECT * FROM relationships WHERE investigation_id=$1', [id]),
    query(TIMELINE_SQL, [id]),
  ]);
  if (!inv.rows[0]) throw new HttpError(404, 'Investigation not found.');
  res.json({ ok: true, mode: 'real', data: {
    investigation: inv.rows[0],
    evidence: evidence.rows,
    entities: entities.rows,
    risk: analyse(evidence.rows, entities.rows),
    graph: buildGraph(evidence.rows, entities.rows, rels.rows),
    timeline: withTimeLabel(timeline.rows),
  } });
};

exports.loadCase = loadCase;
exports.getInvestigationOr404 = getInvestigationOr404;
