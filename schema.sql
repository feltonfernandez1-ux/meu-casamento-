CREATE TABLE IF NOT EXISTS confirmacoes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nome TEXT NOT NULL,
  telefone TEXT NOT NULL UNIQUE,
  presenca TEXT NOT NULL CHECK (presenca IN ('sim','nao')),
  pessoas INTEGER NOT NULL DEFAULT 1,
  mensagem TEXT,
  criado_em TEXT NOT NULL DEFAULT (datetime('now')),
  atualizado_em TEXT NOT NULL DEFAULT (datetime('now'))
);
