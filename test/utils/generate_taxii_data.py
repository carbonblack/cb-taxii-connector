import stix2generator
import json

generator = stix2generator.create_stix_generator()
generated = generator.generate('indicator')
for indicator in generated.values():
	print(indicator.serialize(pretty=True))
