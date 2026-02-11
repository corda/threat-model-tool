

- there should be a version number in the yaml, we start from 2
- we need to refactor 'classic' yaml to 2:
    - children: 
        ID: -> rename this to REFID
- We need to update all yaml file to adhere to the new schema (no legacy anymore)
- src/r3threatmodeling/normalizeYAML.py is an example on how I did previously to port yaml files (refactoring)
- there should be a make task to upgrade a directory (dry run in place etc)