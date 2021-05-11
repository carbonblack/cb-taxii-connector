import logging
import os
from medallion import (
    application_instance, register_blueprints, set_config
)

log = logging.getLogger("medallion")

current_path = os.path.dirname(os.path.abspath(__file__))

configuration = {
    "taxii": {"max_page_size": 100},
    "backend": {"module": "medallion.backends.memory_backend", "module_class": "MemoryBackend",
                "filename": f"{current_path}/mock_taxii_data.json"}
}

def start_mock_server():
    log.setLevel("DEBUG")

    set_config(application_instance, "users", configuration)
    set_config(application_instance, "taxii", configuration)
    set_config(application_instance, "backend", configuration)
    register_blueprints(application_instance)

    application_instance.run()
