#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Nov 16 17:13:27 2020

@author: Vicente Quezada
@modified by: Fabian Astudillo <fabian.astudillos@ucuenca.edu.ec>
"""
import json

# Number of hosts
def statement_p1_1(gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {"num_hosts": {"cardinality": {"field": "src_ip.keyword"}}},
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Get the number of dns requests per hour
def statement_p1(size, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "get_ip": {
                            "terms": {
                                "field": "src_ip.keyword",
                                "min_doc_count":100,
                                "order": {"_count": "desc"},
                                "size": size,
                            }
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Get the number of dns requests per hour
def statement_p2(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dns.rrname.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Get the most requests for a single domain per hour
def statement_p3(item, size, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "dnss": {
                                    "terms": {
                                        "field": "dns.rrname.keyword",
                                        "order": {"_count": "desc"},
                                        "size": 1,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Mean number of queries by minute
def statement_p4(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "times": {
                                    "date_histogram": {
                                        "field": "@timestamp",
                                        "fixed_interval": "1m",
                                        "time_zone": "America/Guayaquil",
                                        "min_doc_count": 1,
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# number of MX register queries per hour
def statement_p6(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "filter_type": {
                                    "filter": {"term": {"dns.rrtype.keyword": "MX"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Number of PTR queries per hour
def statement_p7(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "filter_type": {
                                    "filter": {"term": {"dns.rrtype.keyword": "PTR"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# get the number of different DNS servers queried per hour
def statement_p8(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dest_ip.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# get the number of tld by host
def statement_p9(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.tld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

# get the number of sld by host
def statement_p10(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.sld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

# NXDOMAIN per hour
def statement_p12(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "filter_type": {
                                    "filter": {
                                        "term": {"dns.rcode.keyword": "NXDOMAIN"}
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# From different cities
def statement_p13(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "geoip.city_name.keyword"}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# de paisesdistintos
def statement_p14(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {
                                        "field": "geoip.country_name.keyword"
                                    }
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


# Relacion de flujo por hora
def statement_p15(item, gte, lte):
    query = json.dumps(
        {
            "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "filter_type": {
                                    "filter": {"term": {"dns.rcode.keyword": "NOERROR"}}
                                }
                            },
                        }
                    },
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

def statement_pNX0(item, gte, lte):
    query = json.dumps(
        {
          "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "query"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "unique_ids": {
                                    "cardinality": {"field": "dn.sld.keyword"}
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query


def statement_pNX(item, size, gte, lte):
    query = json.dumps(
        {
          "aggs": {
                "filter_type": {
                    "filter": {"term": {"dns.type.keyword": "answer"}},
                    "aggs": {
                        "filter_ip": {
                            "filter": {"term": {"src_ip.keyword": item}},
                            "aggs": {
                                "NX_filter": {
                                  "filter":{"term": {
                                    "dns.rcode.keyword": "NXDOMAIN"
                                  }},
                                  "aggs":{
                                    "sld_filter":{
                                      "terms":{
                                        #"field": "dn.sld.keyword",
                                        #"script" : "doc['dn.sld.keyword'].value + '.' + doc['dn.tld.keyword'].value",
                                        "script" : "doc['dns.rrname.keyword'].value",
                                        "size": size
                                      }
                                    }
                                  }
                                }
                            }
                        }
                    }
                }
            },
            "size": 0,
            "stored_fields": ["*"],
            "script_fields": {},
            "docvalue_fields": [
                {"field": "@timestamp", "format": "date_time"},
                {"field": "timestamp", "format": "date_time"},
            ],
            "_source": {"excludes": []},
            "query": {
                "bool": {
                    "must": [],
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": gte,
                                    "lte": lte,
                                    "format": "strict_date_optional_time",
                                }
                            }
                        },
                    ],
                    "should": [],
                    "must_not": [],
                }
            },
        }
    )
    return query

# Get member by IP
def getMember(ip):
    query = json.dumps(
        {
            "size": 0,
            "query": {
                "bool": {
                "filter": {"term": {"src_ip.keyword": ip}}
                }
            },
            "aggs": {
                "members": {
                "terms": {
                    "field": "member.keyword",
                    "order": {
                    "firstSeen": "asc"
                    }
                },
                "aggs": {
                    "firstSeen": {
                    "min": {
                        "field": "@timestamp"
                    }
                    }
                }
                }
            }
        }
    )
    return query