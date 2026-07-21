// QR wrapper — uses the vendored Nayuki generator (_qrcodegen.js, MIT), byte mode, ECC level M.
// server-side, emits a self-contained inline SVG (no client JS, CSP-safe).
import { qrcodegen } from "./_qrcodegen.js";

export function qrMatrix(text) {
  const qr = qrcodegen.QrCode.encodeText(text, qrcodegen.QrCode.Ecc.MEDIUM);
  const n = qr.size;
  const m = [];
  for (let r = 0; r < n; r++) {
    const row = [];
    for (let c = 0; c < n; c++) row.push(qr.getModule(c, r)); // getModule(x=col, y=row)
    m.push(row);
  }
  return m;
}

// crisp, scalable svg of the dark modules with a quiet-zone border.
export function qrSvg(text, { quiet = 2 } = {}) {
  const m = qrMatrix(text);
  const n = m.length;
  const dim = n + quiet * 2;
  let path = "";
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++)
      if (m[r][c]) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" shape-rendering="crispEdges"><path d="${path}" fill="#000"/></svg>`;
}
