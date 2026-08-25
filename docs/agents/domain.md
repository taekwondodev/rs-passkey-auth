# Domain docs

Questo repository usa un layout single-context.

## Prima dell'esplorazione

Leggi:

- `CONTEXT.md` alla root.
- Gli ADR in `docs/adr/` che riguardano l'area da modificare.

Se un documento non esiste, procedi senza segnalare l'assenza. Il domain
modeling crea questi documenti quando un termine o una decisione viene
effettivamente risolto.

## Layout

```text
/
├── CONTEXT.md
├── docs/adr/
└── crates/
```

## Vocabolario

Quando un output nomina un concetto di dominio, usa il termine definito in
`CONTEXT.md`. Non sostituirlo con sinonimi che il glossario sconsiglia.

Se il concetto necessario non è ancora definito, trattalo come possibile gap di
domain modeling invece di inventare una nuova terminologia.

## Conflitti ADR

Se un output contraddice un ADR esistente, dichiaralo esplicitamente e valuta
se l'ADR debba essere riaperto. Non sovrascrivere silenziosamente una decisione.
