test_lib := pytest

# Help
help::
	@echo Usage: make [COMMAND]
	@echo Commands:
	@echo help - this help message
	@echo test - run tests for all algorithms
	@echo clean - remove all temporary files

# Run all tests
test::
	$(test_lib) .

# Remove temporary files
clean::
	@rm -rf \
		__pycache__ \
		.pytest_cache
