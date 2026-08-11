const CAIRO_LOGO_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000">
  <defs>
    <linearGradient id="cairo" x1="0" y1="0" x2="0" y2="1">
      <stop offset="30.5%" stop-color="#6237ff"/>
      <stop offset="100%" stop-color="#258eff"/>
    </linearGradient>
  </defs>
  <path d="M500 343.8c16.6 0 33.5 2.2 49.6 6.5 44.2-49.6 124.8-70.5 159.3-56.1 34.7 14.4-10.4 173.7-10.4 173.7 14.1 26.6 24.8 55.6 24.8 85.4 0 110.7-100 187.6-223.4 187.6S276.5 666.4 276.5 553.3c0-31 12.4-59.6 24.8-85.4 0 0-46.9-159.3-12.4-173.7 34.5-14.4 117.2 5.7 161.3 55.4 16.4-3.9 33.1-5.8 49.8-5.8Z" fill="none" stroke="url(#cairo)" stroke-width="20" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M400.7 544.2v12.4M599.3 544.2v12.4" fill="none" stroke="url(#cairo)" stroke-width="20" stroke-linecap="round"/>
  <path d="M518.6 609.2c5.6 0 10.6 3.4 12.7 8.5 2.1 5.1 1 11.1-3 15l-18.6 18.6c-5.4 5.4-14.1 5.4-19.5 0l-18.6-18.6c-3.9-3.9-5.1-9.9-3-15 2.1-5.2 7.2-8.5 12.7-8.5h37.3Z" fill="none" stroke="url(#cairo)" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
  <circle cx="500" cy="500" r="388.6" fill="none" stroke="url(#cairo)" stroke-width="18"/>
</svg>`;

export function GET() {
  return new Response(CAIRO_LOGO_SVG, {
    headers: {
      "Cache-Control": "public, max-age=300, must-revalidate",
      "Content-Type": "image/svg+xml; charset=utf-8",
    },
  });
}
