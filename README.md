## Circuit setup

`circomkit` makes things more convenient but requires a bit of extra setup. To compile a new circuit, you must add an entry to `circuits.json`. Each entry has a key which becomes the name of the instantiated circuit and a value which provides the path to the file containing the template, the name of the template, the names of the public inputs to the circuit, and the value of the parameters for the template.

Then, to compile, run `npx circomkit compile <circuit-name>`. To do the circuit-specific setup step, run `npx circomkit setup <circuit-name>`.

Each compiled circuit can have multiple input files. The inputs are stored in the folder `inputs/<circuit-name>`. To generate a proof using the input stored at `inputs/<circuit-name>/<input-file-name>.json`, run the command `npx circomkit prove <circuit-name> <input-file-name>`. The resulting proof and public values can be viewed in the folder `build/<circuit-name>/<input-file-name>`.