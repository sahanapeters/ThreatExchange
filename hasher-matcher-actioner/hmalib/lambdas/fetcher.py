# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

import json
import typing as t

from threatexchange.threat_updates import ThreatUpdatesDelta, ThreatUpdateJSON
from threatexchange.signal_type.pdq_index import PDQIndex

indexes = {"PDQ" : PDQIndex}

from datetime import datetime

def lambda_handler(event, context):
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")

    pdq_hash = 'new_pdq_at_time_' + current_time
    print(pdq_hash)

    # TODO fetch data from ThreatExchange
    json_update = {'should_delete' : False, "type" : "pdq", "raw_indicator" : pdq_hash}
    stream = ThreatUpdatesDelta(0,0,now)
    stream.updates.append(ThreatUpdateJSON(json_update))

    updates_by_index_type = {
        index_name : [
            update
            for update in stream.updates
            if PDQIndex.can_process_te_update(update)
        ]
        for index_name, index in indexes.items()
    }

    loaded_indexes = {index_name : index.load() for index_name, index in indexes.items()}

    # TODO add TE data to indexer

    return {
        'statusCode': 200,
        'body': json.dumps(threat_exchange_data)
    }

lambda_handler(0,0)
