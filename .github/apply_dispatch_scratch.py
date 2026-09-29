from pathlib import Path
p = Path('pkg/node/node_dispatch.go')
s = p.read_text()

def one(old, new):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'expected 1 match, got {n}: {old[:100]!r}')
    s = s.replace(old, new, 1)

one(
    '\tbatches := make(map[batchTasksKey][]dispatchTask, 4)\n',
    '\tbatches := make(map[batchTasksKey][]dispatchTask, 4)\n'
    '\t// Reuse one worker-local view for the at-most-32 drained tasks.\n'
    '\t// This removes per-group [][]byte allocations from the hot path.\n'
    '\tvar batchScratch [32][]byte\n',
)
one(
'''\t\t\t\tcase 0: // unicast — executed synchronously by the worker goroutine
\t\t\t\t\tbatch := make([][]byte, 0, len(tasks))
\t\t\t\t\torigLens := make([]int, 0, len(tasks))
\t\t\t\t\tfor _, t := range tasks {
\t\t\t\t\t\tbatch = append(batch, t.data)
\t\t\t\t\t\torigLens = append(origLens, t.origLen)
\t\t\t\t\t}
''',
'''\t\t\t\tcase 0: // unicast — executed synchronously by the worker goroutine
\t\t\t\t\tbatch := batchScratch[:len(tasks)]
\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\tbatch[i] = t.data
\t\t\t\t\t}
''')
one('\t\t\t\t\t\torigLen := origLens[0]\n', '\t\t\t\t\t\torigLen := tasks[0].origLen\n')
one(
'''\t\t\t\t\t\t} else {
\t\t\t\t\t\t\tfor _, ol := range origLens {
\t\t\t\t\t\t\t\tn.Collector.RecordSent(ol)
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}
\t\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\t\tif t.owned {
\t\t\t\t\t\t\t\treleaseFrameBuf(batch[i])
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}
''',
'''\t\t\t\t\t\t} else {
\t\t\t\t\t\t\tfor _, t := range tasks {
\t\t\t\t\t\t\t\tn.Collector.RecordSent(t.origLen)
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}
\t\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\t\tif t.owned {
\t\t\t\t\t\t\t\treleaseFrameBuf(batch[i])
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\tbatch[i] = nil
\t\t\t\t\t\t}
''')
one(
'''\t\t\t\t\t} else {
\t\t\t\t\t\tbatch := make([][]byte, 0, len(tasks))
\t\t\t\t\t\torigLens := make([]int, 0, len(tasks))
\t\t\t\t\t\tfor _, t := range tasks {
\t\t\t\t\t\t\tbatch = append(batch, t.data)
\t\t\t\t\t\t\torigLens = append(origLens, t.origLen)
\t\t\t\t\t\t}
\t\t\t\t\t\tn.Dispatcher.BroadcastBatchToAllPeers(n.ctx, batch)
\t\t\t\t\t\tfor _, ol := range origLens {
\t\t\t\t\t\t\tn.Collector.RecordSent(ol)
\t\t\t\t\t\t}
\t\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\t\tif t.owned {
\t\t\t\t\t\t\t\treleaseFrameBuf(batch[i])
\t\t\t\t\t\t\t}
\t\t\t\t\t\t}
\t\t\t\t\t}
''',
'''\t\t\t\t\t} else {
\t\t\t\t\t\tbatch := batchScratch[:len(tasks)]
\t\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\t\tbatch[i] = t.data
\t\t\t\t\t\t}
\t\t\t\t\t\tn.Dispatcher.BroadcastBatchToAllPeers(n.ctx, batch)
\t\t\t\t\t\tfor _, t := range tasks {
\t\t\t\t\t\t\tn.Collector.RecordSent(t.origLen)
\t\t\t\t\t\t}
\t\t\t\t\t\tfor i, t := range tasks {
\t\t\t\t\t\t\tif t.owned {
\t\t\t\t\t\t\t\treleaseFrameBuf(batch[i])
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\tbatch[i] = nil
\t\t\t\t\t\t}
\t\t\t\t\t}
''')
worker = s[s.index('func (n *Node) dispatchWorker'):s.index('// DispatchUrgentFrame')]
if 'origLens' in worker:
    raise SystemExit('origLens remains in dispatchWorker')
p.write_text(s)
