import json

import stix2generator

config = stix2generator.generation.object_generator.TaxiiConnectorConfiguration(optional_property_probability=.25,
                                                                                minimize_ref_properties=False)
object_generator = stix2generator.create_object_generator(object_generator_config=config)


def generate_random_indicator():
    return object_generator.generate('indicator')

def get_manifest_for_indicator(indicator):
    return {
        "date_added": indicator["modified"],
        "id": indicator["id"],
        "media_type": "application/stix+json;version=2.1",
        "version": indicator["modified"]
    }

def generate_collection(n=100):
	collection_data = {"objects":[], "manifest":[]}
	for i in range(0,n):
		indicator = generate_random_indicator()
		manifest = get_manifest_for_indicator(indicator)
		collection_data["objects"].append(indicator)
		collection_data["manifest"].append(manifest)
	return collection_data

print(json.dumps(generate_collection(12)))
