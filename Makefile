.PHONY: test validate python-test plugin-test installer-test release-check doctor scan-only-dummy e2e-dummy install

SKILL_DIR := skills/data-broker-removal

doctor:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) doctor

validate:
	python3 $(SKILL_DIR)/scripts/validate_data_broker_removal.py --skill-dir $(SKILL_DIR)

python-test:
	python3 -m unittest discover -v

plugin-test:
	npm run check

release-check:
	python3 scripts/release_check.py

installer-test:
	python3 -m unittest -v tests.skills.test_data_broker_removal_skill.InstallerTests

test: validate python-test plugin-test release-check

scan-only-dummy:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) scan-only-dummy --workdir .tmp/rightout-scan-only

e2e-dummy:
	python3 $(SKILL_DIR)/scripts/data_broker_removal.py --skill-dir $(SKILL_DIR) e2e-dummy --workdir .tmp/rightout-e2e

install:
	./install.sh
