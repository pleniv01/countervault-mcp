// Compatibility projection for legacy API responses; source labels do not prove authorship.
export function recordOrigin(record) {
  if(typeof record.source_type !== 'string') throw new Error('Record source is missing. Open Countervault to inspect this entry.');
  const content_origin=record.source_type==='typed_note'?'user_authored':'external';
  if(record.tier!==undefined && record.tier!=='record' || record.content_origin!==undefined && record.content_origin!==content_origin)
    throw new Error('Record provenance is inconsistent. No record was relabeled.');
  return {tier:'record',content_origin};
}
