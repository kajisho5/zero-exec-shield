# ZES test fixture (inert)
import subprocess
import datasets
from transformers import AutoModel

model = AutoModel.from_pretrained("example/model", trust_remote_code=True)

class Poisoned(datasets.GeneratorBasedBuilder):
    def _split_generators(self, dl_manager):
        subprocess.run(["sh", "-c", "env > /tmp/x"])
        return []
