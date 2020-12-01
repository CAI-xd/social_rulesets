import shutil
import unicodedata
import os
import re
from datetime import datetime
from typing import Union, TypedDict, List, Iterator

import requests
from requests import Response

OUTPUT_DIRECTORY = 'rulesets'
RULESETS_API_URL = 'https://api.koodous.com/public_rulesets'
RULESET_OUTPUT_TEMPLATE = """\
/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: {analyst.username}
    Rule name: {name}
    Rule id: {rule_id}
    Created at: {created_at}
    Updated at: {updated_at}
    
    Rating: #{rating}
    Total detections: {detections}
*/

{rules}
"""


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode('ascii')
    value = re.sub('[^\w\s-]', '', value).strip().lower()
    value = re.sub('[-\s]+', '-', value)
    return value


class APIPage(TypedDict):
    count: int
    next: Union[str, None]
    previous: Union[str, None]
    results: List[dict]


class Analyst:
    def __init__(self, username: str, **kwargs):
        self.username: str = username


class Ruleset:
    def __init__(self, name: str, rules: str, detections: int, rating: int,
                 created_on: int, modified_on: int, analyst: dict, **kwargs):
        self.rule_id: int = kwargs['id']
        self.name: str = name
        self.rules: str = rules
        self.detections: int = detections
        self.rating: int = rating
        self.created_at = datetime.utcfromtimestamp(created_on)
        self.updated_at = datetime.utcfromtimestamp(modified_on)
        self.analyst: Analyst = Analyst(**analyst)

    def file_output(self) -> str:
        return RULESET_OUTPUT_TEMPLATE.format(**vars(self))

    def save(self, filename):
        with open(filename, 'w') as f:
            f.write(self.file_output())


class Rulesets:
    url: str = RULESETS_API_URL
    default_params = {'social': 'True'}

    def get_params(self, extra_params: Union[dict, None] = None) -> dict:
        params = dict(self.default_params)
        params.update(extra_params or {})
        return params

    def retrieve_page(self, page: int) -> APIPage:
        response: Response = requests.get(self.url, self.get_params({'page': page}))
        response.raise_for_status()
        return response.json()

    def retrieve_all(self) -> Iterator[Ruleset]:
        page = 1
        has_next = True
        while has_next:
            public_rulesets = self.retrieve_page(page)
            has_next = public_rulesets['next'] is not None
            yield from map(lambda result: Ruleset(**result), public_rulesets['results'])
            page += 1

    def save_rulesets(self, output_directory: str):
        os.makedirs(output_directory, exist_ok=True)
        for ruleset in self.retrieve_all():
            filename = f'{slugify(ruleset.name)} ({ruleset.rule_id}).yara'
            ruleset.save(os.path.join(output_directory, filename))


if __name__ == '__main__':
    if os.path.exists(OUTPUT_DIRECTORY):
        shutil.rmtree(OUTPUT_DIRECTORY)
    Rulesets().save_rulesets(OUTPUT_DIRECTORY)
