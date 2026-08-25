# Issue tracker: GitHub

Issue, specifiche e ticket di questo repository vivono in GitHub Issues.
Usa `gh` per tutte le operazioni.

## Convenzioni

- Crea: `gh issue create --title "..." --body "..."`
- Leggi: `gh issue view <number> --comments`
- Elenca: `gh issue list --state open --json number,title,body,labels,comments`
- Modifica il body senza sostituire l'issue:
  `gh issue edit <number> --body-file <path>`
- Commenta: `gh issue comment <number> --body "..."`
- Applica o rimuovi label:
  `gh issue edit <number> --add-label "..."` /
  `gh issue edit <number> --remove-label "..."`
- Chiudi: `gh issue close <number> --comment "..."`

Il repository è `taekwondodev/rs-server`; `gh` lo deduce dal clone.

## Quick issue capture

Usato da `/capture-issue`. Crea un issue con una sola categoria fissa,
`bug` oppure `enhancement`, e con la label di stato `needs-grilling`.
L'issue è intenzionalmente incompleto e non deve ricevere
`ready-for-agent` prima della pubblicazione di una specifica completa.

Quando `/to-spec` completa un issue esistente, aggiorna il body in place e
applica e rimuove le label nella stessa transizione. Non creare un issue
sostitutivo.

## Wayfinding

Usato da `/wayfinder`.

- La map è un issue con label `wayfinder:map`.
- I child ticket sono sub-issue GitHub quando disponibili; altrimenti usa una
  task list nella map e `Part of #<map>` nel child.
- Usa le dipendenze native GitHub per rappresentare i blocker.
- Un ticket è disponibile quando tutti i blocker sono chiusi e non è assegnato.
- Claim: `gh issue edit <n> --add-assignee @me`.
- Resolve: commenta, chiudi e aggiungi alla map un puntatore alla decisione.

## Tracer-bullet tickets

Usato da `/to-tickets` e `/implement`.

Ogni ticket descrive gli strati toccati, Handler/Service/Repository, e il
comportamento da costruire. `/implement` può chiuderlo solo dopo code review
superata e commit creato.
