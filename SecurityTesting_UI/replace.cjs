const fs = require('fs');
const path = require('path');

const dirPath = path.join(__dirname, 'src');

function walkDir(dir, callback) {
    fs.readdirSync(dir).forEach(f => {
        let dirPath = path.join(dir, f);
        let isDirectory = fs.statSync(dirPath).isDirectory();
        isDirectory ? walkDir(dirPath, callback) : callback(path.join(dir, f));
    });
}

const replacements = [
    [/bg-slate-900\/50/g, 'bg-slate-50/50'],
    [/bg-slate-800\/50/g, 'bg-white/50'],
    [/bg-slate-700\/50/g, 'bg-slate-100/50'],
    [/bg-slate-700\/30/g, 'bg-slate-100/80'],
    [/bg-slate-700\/20/g, 'bg-slate-100/50'],
    [/bg-slate-900/g, 'bg-slate-50'],
    [/bg-slate-800/g, 'bg-white'],
    [/bg-slate-700/g, 'bg-slate-100'],
    [/bg-slate-600/g, 'bg-slate-200'],
    [/border-slate-700/g, 'border-slate-200'],
    [/border-slate-600/g, 'border-slate-300'],
    [/text-slate-200/g, 'text-slate-800'],
    [/text-slate-300/g, 'text-slate-700'],
    [/text-slate-400/g, 'text-slate-600'],
    
    // Replace text-white in specific elements (headings, spans)
    [/<h1([^>]*)text-white/g, '<h1$1text-slate-900'],
    [/<h2([^>]*)text-white/g, '<h2$1text-slate-900'],
    [/<span([^>]*)text-white/g, '<span$1text-slate-900'],
    [/(valueClassName \|\| "text-white")/g, '$1'], // skip this one
    [/(valueClassName \|\| ")text-white(")/g, '$1text-slate-900$2'],
    
    // Some buttons that had hover:text-white and bg-slate-700
    // e.g. text-slate-300 hover:text-white bg-slate-700 hover:bg-slate-600
    // became text-slate-700 hover:text-white bg-slate-100 hover:bg-slate-200
    // let's change hover:text-white to hover:text-slate-900 for these
    [/hover:text-white/g, 'hover:text-slate-900'],
];

walkDir(dirPath, function(filePath) {
    if (filePath.endsWith('.tsx') || filePath.endsWith('.ts') || filePath.endsWith('.css')) {
        let content = fs.readFileSync(filePath, 'utf8');
        let newContent = content;
        for (let [pattern, replacement] of replacements) {
            newContent = newContent.replace(pattern, replacement);
        }
        
        if (content !== newContent) {
            fs.writeFileSync(filePath, newContent, 'utf8');
            console.log('Updated', filePath);
        }
    }
});
