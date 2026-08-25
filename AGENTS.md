# rs-server

## Stack

Rust 1.85+, Axum, PostgreSQL tramite deadpool, Redis, WebAuthn passkey, JWT
(EdDSA access e HS256 refresh), Prometheus e Docker Compose.

Il repository è un Cargo workspace con architettura esagonale,
ports-and-adapters. Leggi il layout prima di modificare il codice.

## Workspace layout

Ogni crate ha un ruolo architetturale distinto. La direzione delle dipendenze è
un vincolo:

- `crates/domain-shared`: shared kernel con soli identificatori condivisi, oggi
  `UserId`, senza regole di business.
- `crates/domain-auth`: bounded context auth con entità, porte, `AuthService` e
  `DomainError`. Dipende solo da `domain-shared` e non usa dipendenze
  infra/HTTP.
- `crates/infra-postgres`: implementazione Postgres della porta
  `AuthRepository`. Dipende da `domain-auth` e implementa anche
  `rs_repository_utils::HealthIndicator`.
- `crates/infra-jwt`: implementazione della porta `JwtService`, con
  crittografia JWT e sessioni Redis. Dipende da `domain-auth` e implementa
  anche `HealthIndicator`.
- `crates/http`: adapter Axum con `AppState<R, J>`, handler, DTO wire e
  `HttpError`. Dipende da `domain-auth` e non nomina concretamente
  `infra-postgres::Repository` o `infra-jwt::Jwt`.
- crate binario root `rs-server`: composition root. È l'unico punto che
  conosce tutti i tipi concreti, monomorfizza `AuthService<Repository, Jwt>` e
  costruisce `AppState`.

Le porte restano generiche con dispatch statico. L'unica eccezione `dyn Trait`
è per gli health check. Gli errori di dominio usano un solo `DomainError`, con
una funzione di conversione al confine in ogni crate infrastrutturale.
Le motivazioni sono in ADR-0001 e ADR-0002.

`domain-shared` è un shared kernel di soli identificatori. Leggi la voce
`UserId` in `CONTEXT.md`; quando contiene una regola di business, quella regola
appartiene a un crate di dominio specifico.

Per aggiungere un health indicator, implementa `HealthIndicator` nell'adapter e
aggiungilo al vettore `health_indicators` costruito nel `main.rs` del crate
root. Non modificare i crate di dominio.

Leggi `CONTEXT.md` per il vocabolario del dominio e `docs/adr/` per le decisioni
architetturali. Non duplicare o ridefinire quei contenuti in questo file.

## Setup iniziale

Dopo il clone:

1. Copia `.env.example` in `.env` e valorizza tutte le variabili richieste:
   `JWT_SECRET_KEY`, `JWT_ISSUER`, `JWT_AUDIENCE`, `URL_BACKEND`,
   `SERVER_PORT` e `INTERNAL_PORT`. Genera `JWT_SECRET_KEY` con
   `openssl rand -base64 32`. Sostituisci anche le password `changeme_*`.
2. Mantieni `INTERNAL_PORT` non pubblicato in `compose.yaml`. Se lo cambi,
   aggiorna anche il target hardcoded in `prometheus.yml`.
3. Avvia l'infrastruttura con `docker compose up -d`.
4. Se il servizio viene rinominato, modifica solo il `name` del package root in
   `Cargo.toml`, lascia invariati i nomi dei crate architetturali e aggiorna
   `WEBAUTHN_RP_NAME`.
5. Per attivare strict mode, imposta `default = ["strict"]` nella root
   `Cargo.toml`. La feature root propaga `strict` ai crate workspace.
6. Esegui `cargo build --workspace`. Per ogni warning valuta se usare o
   rimuovere lo scaffold, senza sopprimere il warning. Ripeti la build fino a
   ottenere il risultato atteso per il binario.

Gli item di libreria pubblici non usati possono non produrre un warning
`dead_code`. Questo vale in particolare per `AdminClaims` e per alcuni campi di
`AccessTokenClaims`; non trattare questa assenza di warning come prova che
l'item sia usato.

## Monolith o gateway

Il default è il monolite. In quel caso rimuovi lo scaffold gateway:

- `crates/http/src/middleware/gateway.rs`
- `crates/http/src/middleware/gateway/tests.rs`
- la dichiarazione condizionata del modulo in
  `crates/http/src/middleware/mod.rs`
- `GatewayForward` e il relativo arm in
  `crates/domain-auth/src/security_audit.rs`
- il merge della catch-all proxy route in `crates/http/src/router.rs`
- la feature `gateway` da root `Cargo.toml`,
  `crates/http/Cargo.toml` e `crates/domain-auth/Cargo.toml`

Se il servizio deve essere un gateway, mantieni lo scaffold, sostituisci
`proxy_stub` con il proxy reale e registra le route downstream nel blocco
condizionato di `router.rs`.

## Nuovi bounded context

Auth è un bounded context composto da `domain-auth`, `infra-postgres`,
`infra-jwt` e dalla parte auth di `http`. Una nuova capability, come payments o
notifications, deve avere il proprio gruppo di crate, non diventare un modulo
di `domain-auth`.

Un nuovo contesto segue questo schema:

- `crates/domain-<name>` per entità, porte, servizio, DTO, comandi ed errori.
- `crates/infra-<tech>` per ogni adapter infrastrutturale.
- handler e DTO HTTP nel modulo corrispondente, oppure un nuovo crate
  `http-<name>` se le esigenze divergono davvero.
- wiring del servizio nel composition root.

Il nuovo crate di dominio dipende solo da `domain-shared`. Per riferire un
utente usa `domain_shared::UserId`, non `domain_auth::User`. Ogni adapter
traduce i propri errori al tipo di dominio al confine. Gli adapter che
richiedono health check implementano `HealthIndicator` e vengono aggiunti al
vettore del composition root.

## CORS

CORS viene applicato nel composition root e configurato in
`crates/http/src/config.rs` tramite `OriginConfig` e `create_cors_layer`.

Se il backend viene consumato solo da client nativi o mobile, rimuovi il layer
CORS, la configurazione correlata, `ORIGIN_FRONTEND` e il wiring associato.
Mantieni `URL_BACKEND`, che viene usato anche come `rp_id` WebAuthn.

## Auth system

Prima di modificare l'autenticazione, leggi gli ADR pertinenti:

- ADR-0003 per la strategia access/refresh token e la reuse detection.
- ADR-0004 per la derivazione HKDF da un singolo secret.
- ADR-0005 per la separazione tra dati dei claims e crittografia.
- ADR-0008 per i recovery codes.
- `CONTEXT.md` per il vocabolario auth.

## Dev cycle

### Issue tracker

Gli issue, le specifiche e i ticket vivono in GitHub Issues e si gestiscono con
`gh`. Vedi `docs/agents/issue-tracker.md`.

### Issue labels

Il dev-cycle usa `needs-grilling` per un issue iniziale incompleto e
`ready-for-agent` quando la specifica è completa. Vedi
`docs/agents/triage-labels.md`.

### Domain docs

Repository single-context: leggi `CONTEXT.md` prima dell'esplorazione e gli ADR
pertinenti prima di modificare un'area. Vedi `docs/agents/domain.md`.