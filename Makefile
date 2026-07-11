.PHONY: test validate doctor scan-only-dummy e2e-dummy

SKILL_DIR := skills/data-broker-removal

doctor:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) doctor

scan-only-dummy:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) scan-only-dummy --workdir .tmp/rightout-scan-only

e2e-dummy:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) e2e-dummy --workdir .tmp/rightout-e2e

validate:
	python3 $(SKILL_DIR)/scripts/validate_data_broker_removal.py --skill-dir $(SKILL_DIR)

test: validate
	python3 -m unittest tests.skills.test_data_broker_removal_skill

