const sqlite3 = require("sqlite3").verbose();
const path = require("path");

// caminho da base de dados
const dbPath = path.resolve(__dirname, "../data/tickets.db");

// email passado como argumento
const email = process.argv[2];

if (!email) {
    console.log("Usage: node scripts/promote_admin.js <email>");
    process.exit(1);
}

const db = new sqlite3.Database(dbPath);

db.run(
    "UPDATE users SET role = 'admin' WHERE email = ?",
    [email],
    function (err) {
        if (err) {
            console.error("Erro:", err.message);
            process.exit(1);
        }

        if (this.changes === 0) {
            console.log("Nenhum utilizador encontrado com esse email.");
        } else {
            console.log(`Utilizador ${email} promovido a ADMIN.`);
        }

        db.close();
    }
);