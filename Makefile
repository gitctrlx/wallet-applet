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

.DEFAULT_GOAL := all
.PHONY: all help check test bench fmt lint build cap run shell clean tasks ci

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
