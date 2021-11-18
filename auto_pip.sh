#!/bin/bash
echo "[x] Checking setup.py"
python3 setup.py check -r -s
echo "[x] Creating pypi Package"

python3 setup.py sdist bdist_wheel 2>stderr.log 1>stdout.log

 if grep -q "error:" stderr.log
	then
		echo "[x] Creating pypi failed.."
		cat stderr.log
	else
		echo "[x] pypi Package was created successfully"
		read -p "Do you want to upload? (y/n)?" USER_INPUT
		if [ "$USER_INPUT" = "y" ]; then
			echo "[x] Uploading pypi Package"
			twine upload dist/*
		fi
 fi
 
echo "[x] Done"
