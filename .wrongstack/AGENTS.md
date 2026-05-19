# AGENTS.md

This file is loaded into WrongStack's system prompt as project context.
Keep it concise, factual, and durable: write the information future agents
need before they touch this codebase.

## Project brief

- **Purpose:** _What does this project do, and why does it exist?_
- **Primary users:** _Who uses it: developers, operators, customers, internal systems?_
- **Runtime/deployment:** _Where does it run: CLI, server, browser, worker, library, package?_
- **Main entry points:** _Which files or commands should an agent inspect first?_

## How to work safely

- _Project-specific rules the agent should always follow._
- _Files, generated artifacts, migrations, or config the agent should not edit without asking._
- _Preferred style or architecture choices that are not obvious from the code._

## Commands

- **Build:** `go build ./...`
- **Test:** `go test ./...`
- **Lint:** `make lint`
- **Run locally:** `go run .`

## Architecture notes

_Summarize the important modules, data flow, boundaries, and ownership rules.
Mention anything a newcomer might misread._

## Domain knowledge

_Business rules, acronyms, invariants, external services, and notes where the
code looks unusual but is intentional._

## Verification checklist

- _What should be run after code changes?_
- _What manual smoke test proves the common path still works?_
- _What failure modes deserve extra attention?_

## Useful pointers

- _Docs, dashboards, runbooks, issue trackers, design notes, or owner contacts._
