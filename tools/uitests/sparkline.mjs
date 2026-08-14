/* The sparklines.

   No build step and no external script may load, so these are drawn by hand.
   A chart that misplaces a point is worse than no chart, so the arithmetic is
   pinned: the line has to fit its box, scale to its own values, and say what
   period it covers. */
import "./stub-dom.mjs";
const { sparkline, trafficSpark, sparkCaption } =
  await import("../../static/js/sparkline.js");

let fail = 0;
const ok = (c, m) => { console.log((c ? "  PASS  " : "  FAIL  ") + m); if (!c) fail++; };
const points = (svg, which = 0) =>
  [...svg.matchAll(/<polyline points="([^"]+)"/g)].map(m => m[1])[which]
    .split(" ").map(p => p.split(",").map(Number));

let svg = sparkline([0, 5, 10], { width: 100, height: 20 });
let p = points(svg);
ok(p.length === 3, "one point per value");
ok(p[0][0] === 1 && Math.round(p[2][0]) === 99, "the line spans the full width");
ok(p.every(([x, y]) => y >= 0 && y <= 20), "and stays inside the box");
ok(p[0][1] > p[2][1], "a rising series rises: y is inverted for screen coordinates");

ok(points(sparkline([3, 3, 3]))[0][1] === points(sparkline([3, 3, 3]))[2][1],
   "a flat series draws flat");
ok(/polyline/.test(sparkline([0, 0, 0])),
   "all zeroes still draws, rather than dividing by zero");
ok(points(sparkline([1, 2]))[1][1] < points(sparkline([1, 200]))[1][1] === false,
   "each line scales to its own values, so shape is comparable and height is not");
ok(sparkline([]) === '<span class=sub>&mdash;</span>', "nothing recorded says so");
ok(points(sparkline([1]))[0].length === 2, "a single point does not divide by zero");

const two = trafficSpark({ req: [1, 2, 3], e5: [0, 1, 0] });
ok((two.match(/<polyline/g) || []).length === 2,
   "errors are drawn as a second line over the requests");
ok(/var\(--down\)/.test(two), "in the colour that means trouble");
const one = trafficSpark({ req: [1, 2, 3], e5: [0, 0, 0] });
ok((one.match(/<polyline/g) || []).length === 1,
   "and not drawn at all when there were none");
ok(/no traffic recorded yet/.test(trafficSpark({ req: [] })),
   "an empty history says so rather than drawing an empty box");

const now = 1700000000;
ok(sparkCaption([now, now + 1800]) === "last 30 min", "the caption dates the line");
ok(sparkCaption([now, now + 7200]) === "last 2 h", "in hours once it is long enough");
ok(sparkCaption([]) === "", "and says nothing when there is nothing");

ok(!/<script|onerror=/i.test(sparkline([1, 2], { label: '"><script>x</script>' })),
   "a label cannot inject markup");

/* -- the scale floor --------------------------------------------------------
   Scaled purely to its own peak, a flat 1 request a minute fills the box
   solid and reads as MORE traffic than a real rush on the row above it. */
const yTop = svg => Math.min(...[...svg.matchAll(/[\d.]+,([\d.]+)/g)].map(m => Number(m[1])));
ok(yTop(sparkline([1,1,1,1], {height:24, floor:10})) > 18,
   "with a floor, a trickle draws as the low band it is");
ok(yTop(sparkline([120,150,90], {height:24, floor:10})) < 4,
   "while anything actually busy still climbs to the top");
ok(yTop(trafficSpark({req:[1,1,1,1], e5:[]}, {})) > 18,
   "the traffic chart applies it: one probe a minute is not a wall");
ok(/no traffic in the window/.test(trafficSpark({req:[0,0,0], e5:[0,0,0]}, {})),
   "a window of nothing says so instead of drawing a flat line of zero");
/* errors share the requests' scale: three errors over three hundred requests
   are a hairline, not a second mountain drawn over the first */
const both = trafficSpark({req:[300,300,300], e5:[3,0,3]}, {});
const errSvg = "<svg" + both.split("<svg")[2];
ok(yTop(errSvg) > 20, "errors are drawn on the same scale as the requests");

console.log(fail ? `\n${fail} failed` : "\nthe sparklines draw what they are given");
process.exit(fail ? 1 : 0);
