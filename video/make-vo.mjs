// Doris demo-video narration with Fish Audio (library voices only, no cloned real people).
// The key is read from FISH_ENV (default: the Tuesday Never Happened .env) and never printed or copied.
// Output -> video/vo/: one mp3 per cue, guide-track.mp3, narration.srt, cues.md
// Usage: node video/make-vo.mjs [--force]      (needs ffmpeg + ffprobe on PATH)
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'video', 'vo');
fs.mkdirSync(OUT, { recursive: true });
const ENV = process.env.FISH_ENV || path.join(ROOT, '..', 'tuesday-never-happened', '.env');
const KEY = (fs.readFileSync(ENV, 'utf8').match(/^FISH_AUDIO_API_KEY=(.*)$/m)?.[1] || '').trim();
if (!KEY) throw new Error('FISH_AUDIO_API_KEY missing');

const VOICE = {
  narrator: '0327fdb5da9e4fd782899a8058c8ae2b', // measured narrator (Fish library voice)
  doris: 'fb4f0464f53e4f939d00a7c20d17d143',    // "Grandma": old, warm (Fish library voice)
};

// [cue, speaker, planned start (s), text, speed] — pictures for each cue are in video/SCRIPT.md
const CUES = [
  ['01', 'narrator', 0.5, 'Every year, older people lose billions to email scams. Their children usually find out afterwards.', 0.97],
  ['02', 'narrator', 8.0, 'Meet Doris. A fictional eighty-one-year-old, run by an AI agent on Fly dot io Sprites.', 0.97],
  ['03', 'narrator', 16.0, 'Forward her a scam, and she tells you, in plain words, whether it is one. Then she deals with them herself.', 1.0],
  ['04', 'doris', 26.0, "Dear Barrister James, well that's a surprise. I didn't know I had a relative with that sort of money. Reg would've said it's too good to be true, but Reg always was a worrier. Which relative was it, dear?", 0.92],
  ['05', 'narrator', 44.0, 'She writes from her own address. Slow, kind, endless questions. Your family never appears.', 1.0],
  ['06', 'narrator', 53.0, 'Every case is on the record. Scammer text is untrusted, links are made unclickable, and every step is hash-chained.', 1.0],
  ['07', 'narrator', 64.0, 'When a scammer sends a link, it opens in a second Sprite: a throwaway computer that rewinds itself to a clean snapshot after every visit.', 1.0],
  ['08', 'narrator', 76.0, 'It holds no keys. Every one of Doris\'s services refuses it. Her home gets through; the trap gets four hundred and three.', 1.0],
  ['09', 'narrator', 88.0, 'Keys live only in Sprites connectors: AgentMail for her inbox, DeepSeek for her judgement and her voice, Box for the evidence, Pinecone to spot a repeat campaign.', 1.0],
  ['10', 'narrator', 102.0, 'Measured: twenty-nine of twenty-nine scams engaged. None of nineteen genuine emails. And an email that gives orders to the AI is never judged safe.', 1.0],
  ['11', 'narrator', 116.0, 'Daisy, the phone granny, talked to scammers. Doris clicks their links, keeps the evidence, and never sends a penny.', 0.97],
  ['12', 'doris', 126.0, 'Go on then, dear. Try to scam me.', 0.9],
  ['13', 'narrator', 130.0, 'Doris. Built on Fly dot io Sprites.', 0.95],
];

async function tts(text, ref, speed) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const r = await fetch('https://api.fish.audio/v1/tts', {
      method: 'POST',
      headers: { Authorization: `Bearer ${KEY}`, 'Content-Type': 'application/json', model: 's1' },
      body: JSON.stringify({ text, reference_id: ref, format: 'mp3', mp3_bitrate: 192, latency: 'normal', prosody: { speed, volume: 0 } }),
    });
    if (r.ok) return Buffer.from(await r.arrayBuffer());
    console.warn(`  attempt ${attempt}: HTTP ${r.status}`);
    await new Promise((res) => setTimeout(res, 1500 * attempt));
  }
  throw new Error('TTS failed');
}
const dur = (f) => Number(execFileSync('ffprobe', ['-v', 'error', '-show_entries', 'format=duration', '-of', 'csv=p=0', f]).toString().trim());
const ts = (s) => {
  const ms = Math.round(s * 1000), h = Math.floor(ms / 3600000), m = Math.floor(ms / 60000) % 60, sec = Math.floor(ms / 1000) % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')},${String(ms % 1000).padStart(3, '0')}`;
};
const mmss = (s) => `${Math.floor(s / 60)}:${(s % 60).toFixed(1).padStart(4, '0')}`;

const placed = [];
let prevEnd = 0;
for (const [cue, who, planned, text, speed] of CUES) {
  const raw = path.join(OUT, `${cue}-${who}.raw.mp3`);
  const file = path.join(OUT, `${cue}-${who}.mp3`);
  if (!fs.existsSync(raw) || process.argv.includes('--force')) {
    process.stdout.write(`cue ${cue} (${who})… `);
    fs.writeFileSync(raw, await tts(text, VOICE[who], speed));
  } else process.stdout.write(`cue ${cue} cached… `);
  execFileSync('ffmpeg', ['-y', '-i', raw, '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11', '-ar', '48000', '-b:a', '192k', file], { stdio: 'ignore' });
  const d = dur(file);
  const start = Math.max(planned, prevEnd + 0.5);
  placed.push({ cue, who, text, file, start, d });
  prevEnd = start + d;
  console.log(`${d.toFixed(1)}s @ ${mmss(start)}`);
}

const args = ['-y'];
placed.forEach((p) => args.push('-i', p.file));
const total = prevEnd + 2;
const filters = placed.map((p, i) => `[${i}:a]adelay=${Math.round(p.start * 1000)}|${Math.round(p.start * 1000)},apad[a${i}]`).join(';');
const mix = placed.map((_, i) => `[a${i}]`).join('') + `amix=inputs=${placed.length}:normalize=0,atrim=0:${total.toFixed(2)}[out]`;
args.push('-filter_complex', `${filters};${mix}`, '-map', '[out]', '-ac', '2', '-ar', '48000', '-b:a', '192k', path.join(OUT, 'guide-track.mp3'));
execFileSync('ffmpeg', args, { stdio: 'ignore' });

fs.writeFileSync(path.join(OUT, 'narration.srt'), placed.map((p, i) => `${i + 1}\n${ts(p.start)} --> ${ts(p.start + p.d)}\n${p.who === 'doris' ? 'DORIS: ' : ''}${p.text}\n`).join('\n'));
fs.writeFileSync(path.join(OUT, 'cues.md'), `# Narration cue sheet\n\n| Cue | Voice | Starts | Length | Line |\n|---|---|---|---|---|\n${placed.map((p) => `| ${p.cue} | ${p.who} | ${mmss(p.start)} | ${p.d.toFixed(1)}s | ${p.text} |`).join('\n')}\n\nNarration ends at ${mmss(prevEnd)}.\n`);
console.log(`\nDone -> ${OUT}`);
