// Inlines engine.js and the gzip example into template.html to produce index.html.
const fs = require('fs');
let t = fs.readFileSync('template.html', 'utf8');
t = t.replace('/*ENGINE*/', () => fs.readFileSync('engine.js', 'utf8'))
     .replace('/*GZ*/', () => fs.readFileSync('gz.txt', 'utf8').trim());
fs.writeFileSync('index.html', t);
console.log('index.html written, ' + t.length + ' bytes');
