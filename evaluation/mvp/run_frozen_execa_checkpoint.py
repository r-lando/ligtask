"""First-use Execa example selected after freezing the production rules."""
import subprocess
import sys
from run_frozen_alias_checkpoint import main as run_case

FROZEN_LF_SHA256 = "82450c09ec5c1c89e1288d240b50051c9cdb04622596ff7489e530b54b100a30"
SOURCE_SHA256 = "64d314bfe378dc96a2c1aebcd45adff8291a45a1c46e5d4b033b49b33a6bda94"


if __name__ == "__main__":
    try:
        raise SystemExit(run_case(source_name="execa.js", source_hash=SOURCE_SHA256,
                                 frozen_fingerprint=FROZEN_LF_SHA256,
                                 result_name="frozen-execa-checkpoint"))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Checkpoint invalid: {type(error).__name__}. No new result produced.", file=sys.stderr)
        raise SystemExit(2)
