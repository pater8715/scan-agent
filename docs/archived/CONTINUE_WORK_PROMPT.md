# Continue Work - AI Agent Instructions

Use this prompt when resuming work on ScanAgent with a new AI agent or session.

---

## 🤖 PROMPT FOR AI AGENTS

```
I need to continue working on the ScanAgent project. Here's the context:

**Project:** ScanAgent - Intelligent Vulnerability Scanner
**Repository:** https://github.com/pater8715/scan-agent
**Current Version:** 3.0.0
**Your Role:** Senior Python/Security Developer

**IMPORTANT: Read these files first (in order):**
1. PROJECT_CONTEXT.md - Complete project overview
2. ROADMAP.md - Current tasks and priorities
3. VERSION.md - Version history
4. QUICK_REFERENCE_v3.0.md - Quick technical reference

**Current Priority:** [SPECIFY: e.g., "Phase 6: File Management Enhancement"]

**Specific Task:** [SPECIFY: e.g., "Implement Phase 2: Enhanced metadata system"]

**Key Constraints:**
- ✅ Maintain backward compatibility (no breaking changes)
- ✅ Follow existing code style and patterns
- ✅ Update documentation for all changes
- ✅ Test changes before committing
- ✅ Commit with descriptive messages following convention
- ❌ Do NOT modify core scanning logic without approval
- ❌ Do NOT change database schema without migration plan
- ❌ Do NOT add new dependencies without justification

**Expected Output:**
1. Working code implementation
2. Updated tests (if applicable)
3. Updated documentation
4. Git commit with proper message
5. Update to ROADMAP.md marking tasks complete

**Questions to ask before starting:**
1. What files need to be modified?
2. Are there any breaking changes?
3. Do I need to update the database schema?
4. What tests should be added/modified?
5. What documentation needs updating?

Please confirm you've read the context files and understand the task before proceeding.
```

---

## 📋 QUICK START CHECKLIST

When starting a new work session:

- [ ] Read `PROJECT_CONTEXT.md` (understand the project)
- [ ] Read `ROADMAP.md` (know current priorities)
- [ ] Check `VERSION.md` (understand version history)
- [ ] Review recent commits (`git log -5`)
- [ ] Check current branch (`git branch`)
- [ ] Verify working directory is clean (`git status`)
- [ ] Activate virtual environment (`source venv/bin/activate`)
- [ ] Check server is NOT running (`ps aux | grep uvicorn`)
- [ ] Review open issues on GitHub
- [ ] Understand the specific task from `ROADMAP.md`

---

## 🎯 COMMON TASKS

### Task 1: Add New Feature

```bash
# 1. Create feature branch
git checkout -b feature/your-feature-name

# 2. Implement feature
# (Edit files, add tests, update docs)

# 3. Test locally
./start-web.sh
# Test the feature manually

# 4. Commit changes
git add .
git commit -m "feat: add your feature description"

# 5. Push and create PR
git push origin feature/your-feature-name

# 6. Update ROADMAP.md
# Mark task as complete, add new tasks if needed
```

### Task 2: Fix Bug

```bash
# 1. Create bugfix branch
git checkout -b fix/bug-description

# 2. Fix the bug
# (Edit files, add regression test)

# 3. Test fix
./start-web.sh
# Verify bug is fixed

# 4. Commit changes
git add .
git commit -m "fix: resolve bug description"

# 5. Push
git push origin fix/bug-description

# 6. Update ROADMAP.md if it was a known issue
```

### Task 3: Update Documentation

```bash
# 1. Edit documentation files
# docs/, README.md, etc.

# 2. Verify links work
# Check all markdown links

# 3. Commit
git add .
git commit -m "docs: update documentation for XYZ"

# 4. Push
git push origin master
```

---

## 🔍 DEBUGGING GUIDE

### Server Won't Start

```bash
# Check if port 8000 is in use
sudo lsof -i :8000

# Kill existing process
sudo kill -9 <PID>

# Check Python environment
which python
python --version  # Should be 3.12+

# Verify dependencies
pip list | grep fastapi
```

### Scans Failing

```bash
# Check tool installation
which nmap
which nikto
which gobuster

# Verify permissions
sudo nmap --version

# Check logs
tail -f /tmp/scanagent.log  # (if logging is configured)
```

### Reports Not Generating

```bash
# Check output directories exist
ls -la storage/active/
ls -la reports/

# Verify permissions
chmod -R 755 storage/
chmod -R 755 reports/

# Check parser
python -c "from webapp.utils.report_parser import ScanResultParser; print('OK')"
```

---

## 📝 COMMIT MESSAGE CONVENTION

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `style`: Code style (formatting, no logic change)
- `refactor`: Code refactoring
- `perf`: Performance improvement
- `test`: Adding tests
- `chore`: Build process, dependencies

**Examples:**
```
feat(parser): add CVE detection to vulnerability analyzer

Implements CVE lookup from NVD database for known vulnerabilities.
Adds caching to reduce API calls.

Closes #42
```

```
fix(api): correct scan status endpoint response format

scan_id was returned as int but should be string.
Updated type hints and validation.

Fixes #38
```

---

## 🚀 DEPLOYMENT CHECKLIST

Before deploying to production:

- [ ] All tests passing (`pytest`)
- [ ] No critical bugs in issue tracker
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Version bumped in `VERSION.md`
- [ ] Git tag created (`git tag vX.Y.Z`)
- [ ] Code reviewed (if team member available)
- [ ] Database migrations tested (if applicable)
- [ ] Backup plan in place
- [ ] Rollback procedure documented

---

## 📚 USEFUL COMMANDS

```bash
# View project statistics
git log --oneline | wc -l  # Total commits
find . -name "*.py" | xargs wc -l  # Total lines of Python

# Find TODO comments
grep -r "TODO" src/ webapp/

# Check code quality
flake8 src/ webapp/  # (if flake8 installed)
pylint src/scanagent/  # (if pylint installed)

# Database inspection
sqlite3 scanagent.db ".tables"
sqlite3 scanagent.db "SELECT * FROM scans LIMIT 5;"

# Clean up generated files
rm -rf reports/* outputs/* storage/active/* storage/metadata/*
```

---

## ⚠️ CRITICAL FILES - DO NOT DELETE

- `src/scanagent/agent.py` - Core scanning logic
- `webapp/api/scans.py` - API endpoints
- `webapp/utils/report_parser.py` - Intelligence layer
- `src/scanagent/database.py` - Database operations
- `scanagent.db` - Production database
- `requirements.txt` - Dependencies
- `.git/` - Version control history

---

## 🎓 LEARNING RESOURCES

**FastAPI:**
- https://fastapi.tiangolo.com/

**Nmap:**
- https://nmap.org/book/man.html

**Python Async:**
- https://docs.python.org/3/library/asyncio.html

**SQLite:**
- https://www.sqlite.org/docs.html

---

**Last Updated:** November 13, 2025  
**Maintainer:** pater8715# ScanAgent - Project Roadmap & Task Management

**Last Updated:** November 13, 2025  
**Current Version:** 3.0.0  
**Status:** 🟢 Production Ready
