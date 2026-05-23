# Makefile for meowl-applet (JavaCard + Gradle)
#
# Wraps the Gradle wrapper with concise, Cargo-style targets. The default
# target mirrors the verification gate in `.github/workflows/ci.yml`:
# spotlessCheck + :tests:test. Run `make help` for the full list.
#
# Cross-platform: detects Windows and dispatches to gradlew.bat; everywhere
# else (Linux, macOS, Git Bash on Windows) it uses the POSIX gradlew script.

ifeq ($(OS),Windows_NT)
	GRADLE := .\gradlew.bat
else
	GRADLE := ./gradlew
endif

GRADLE_FLAGS ?= --no-daemon
CAP ?= $(abspath applet/build/cap/meowl-applet.cap)
PIN ?= 123456
PUK ?= 12345678
SEED ?=
CDKenc ?= 5A9E63D03BADBC2A240FE8F534709EDF
CDKmac ?= 7CCC1E79D64FC5FA263B8F2955282998
CDKkek ?= B040703EC3DE23EE8AE4CFB6D632AA80
GP_KEYS ?= --key-enc $(CDKenc) --key-mac $(CDKmac) --key-kek $(CDKkek)

.DEFAULT_GOAL := all
.PHONY: all help check test bench fmt lint build cap install uninstall init reset-card run shell clean tasks ci

# Default target — the verification gate the user asked for: enforces the
# Spotless format contract, then runs the full applet test suite.
all: ci

# Print a short summary of every public target.
help:
	@echo meowl-applet make targets
	@echo   make             alias for 'make all' -- spotlessCheck + :tests:test
	@echo   make all         spotlessCheck + :tests:test (CI-equivalent gate)
	@echo   make check       ./gradlew spotlessCheck
	@echo   make test        ./gradlew :tests:test
	@echo   make bench ARGS=.. ./gradlew :tools:run --args="bench ARGS"
	@echo   make fmt         ./gradlew spotlessApply (auto-format in place)
	@echo   make lint        alias for 'make check'
	@echo   make build       ./gradlew :applet:buildCap
	@echo   make cap         alias for 'make build'
	@echo   make install     build CAP and install it with default CDK ENC/MAC/KEK
	@echo   make uninstall   uninstall applet/package with default CDK ENC/MAC/KEK
	@echo   make init        initialize fresh applet: PKI + PIN/PUK + seed
	@echo   make reset-card  factory reset installed applet state
	@echo   make run ARGS=.. ./gradlew :tools:run --args=ARGS
	@echo   make shell       ./gradlew :tools:run --args=shell
	@echo   make ci          full CI pipeline: spotlessCheck + buildCap + :tests:test
	@echo   make tasks       ./gradlew tasks --all (list every Gradle task)
	@echo   make clean       ./gradlew clean (remove every build/ directory)

# Enforce the Spotless format contract across every Gradle subproject.
check:
	$(GRADLE) $(GRADLE_FLAGS) spotlessCheck

# Run the full applet test suite (jcardsim integration + protocol tests).
test:
	$(GRADLE) $(GRADLE_FLAGS) :tests:test

# Run the host-side card benchmark CLI. Pass ARGS, e.g. ARGS="-p 123456 --samples 30".
bench:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="bench $(ARGS)"

# Auto-format in place (Java + Kotlin Gradle DSL via Spotless).
fmt:
	$(GRADLE) $(GRADLE_FLAGS) spotlessApply

lint: check

# Build the deployable JavaCard applet artefact.
build:
	$(GRADLE) $(GRADLE_FLAGS) :applet:buildCap

cap: build

install: build
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="gp install $(GP_KEYS) $(CAP)"

uninstall:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="gp uninstall $(GP_KEYS)"

init:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="bootstrap -p $(PIN) --puk $(PUK)$(if $(SEED), --seed $(SEED))"

reset-card:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="reset --confirm"

# Run the host-side CLI. Pass ARGS to forward arguments, e.g.
#   make run ARGS="info --json"
run:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="$(ARGS)"

# Drop into the interactive REPL with persistent SC session.
shell:
	$(GRADLE) $(GRADLE_FLAGS) :tools:run --args="shell"

# Reproduce the GitHub Actions verification job locally (matches ci.yml).
ci: check build test

# List every Gradle task (useful when discovering subproject-scoped tasks).
tasks:
	$(GRADLE) $(GRADLE_FLAGS) tasks --all

# Remove every build/ directory under the workspace.
clean:
	$(GRADLE) $(GRADLE_FLAGS) clean
