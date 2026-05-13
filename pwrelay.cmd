@echo off
rem Windows entry point for pwrelay. Drops you into the same Python
rem implementation Mac/Linux use via the `pwrelay` bash shim.
python "%~dp0pwrelay.py" %*
