from itertools import chain

from influxdb_client import InfluxDBClient

xml_head = """<?xml version="1.0" encoding="utf-8" standalone="yes" ?>
<edmx:Edmx Version="1.0" xmlns:edmx="http://schemas.microsoft.com/ado/2007/06/edmx"
           xmlns:m="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://schemas.microsoft.com/ado/2007/06/edmx ">
    <edmx:DataServices m:DataServiceVersion="2.0">
        <Schema Namespace="InfluxDBSchema" xmlns="http://schemas.microsoft.com/ado/2006/04/edm"
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xsi:schemaLocation="http://schemas.microsoft.com/ado/2006/04/edm ">"""

xml_foot = """
        </Schema>
    </edmx:DataServices>
</edmx:Edmx>"""

influx_type_to_edm_type = {
    'float': 'Edm.Double',  # influxdb stores floats in a float64 format
    'integer': 'Edm.Int64',  # influxdb stores integers as 64-bit signed
    'string': 'Edm.String'
}


def get_edm_type(influx_type):
    if influx_type is None:
        return 'Edm.String'
    else:
        return influx_type_to_edm_type[influx_type]


def mangle_measurement_name(m_name):
    """corresponds to unmangle_measurement_name in influxdbds.py"""
    m_name = m_name.replace(' ', '_sp_')
    m_name = m_name.replace('-', '_dsh_')
    return m_name


def mangle_bucket_name(bucket):
    bucket = bucket.strip('_')  # edmx names cannot begin with '_'
    bucket = bucket.replace('-', '_dsh_')
    return bucket


def bucket_name__measurement_name(bucket_name, m_name):
    return '{}__{}'.format(
        mangle_bucket_name(bucket_name),
        mangle_measurement_name(m_name)
    )
def mangle_field_name(field_name):
    return field_name.replace(' ', '_sp_').replace('.', '_dot_')

class InfluxDB(object):
    def __init__(self, connection):
        self.min_timerange = '90d'
        try:
            self.client = InfluxDBClient(url=connection['url'], token=connection['token'], org=connection["org"])
            self.query_api = self.client.query_api()
        except Exception as e:
            print("Failed to connect to initialize Influx Odata container")
            print(str(e))
            raise ConnectionError()
        try:
            bucket = connection['bucket']
            if isinstance(bucket, str):
                self.buckets = bucket.split(',')
            else:
                self.buckets = list()
        except:
            print("Bucket details not valid")
            raise ValueError()

    def fields(self, bucket, measurement):
        """returns a tuple of dicts where each dict has attributes (name, type, edm_type)"""

        fields_query = 'from (bucket: "{}") \
        |> range(start: -{}, stop: now()) \
        |> filter(fn: (r) => (r._measurement == "{}")) \
        |> keep(columns: ["_field"]) \
        |> group() \
        |> distinct(column: "_field") \
        |> limit(n: 200) \
        |> sort()'.format(bucket, self.min_timerange, measurement)

        tags_query = 'from (bucket: "{}") \
        |> range(start: -{}, stop: now()) \
        |> filter(fn: (r) => (r._measurement == "{}")) \
        |> keys()  \
        |> keep(columns: ["_value"]) \
        |> distinct() \
        |> filter(fn: (r) => r._value != "_measurement" and r._value != "_field") \
        |> filter(fn: (r) => r._value != "_time" and r._value != "_start" and r._value != "_stop" and r._value != "_value") \
        |> sort() \
        |> limit(n: 200)'.format(bucket, self.min_timerange, measurement)

        fields_rs = self.query_api.query(fields_query)
        tags_rs = self.query_api.query(tags_query)
        fields = []
        tags = []
        try:
            fields = [(_f.values['_value'], 'float') for _f in fields_rs[0].records]
        except:
            pass
        try:
            tags = [(_t.values['_value'], 'string') for _t in tags_rs[0].records]
        except:
            pass
        fields.extend(tags)

        # tags_rs = self.client.query('SHOW TAG KEYS', database=db_name)
        # expand and deduplicate
        #fields = set(tuple(f.items()) for f in chain(*chain(fields_rs, tags_rs)))
        fields = (dict(
            name= mangle_field_name(f[0]),
            type=f[1],
            edm_type=get_edm_type(f[1])
        ) for f in fields)
        return tuple(fields)

    @property
    def measurements(self):
        measurements = []

        for each_bucket in self.buckets:
            q = 'import "influxdata/influxdb/v1" v1.tagValues(bucket: "{}", tag: "_measurement", predicate: (r) => true, start: -{})'\
                .format(each_bucket, self.min_timerange)
            #'import "influxdata/influxdb/v1" v1.measurements(bucket: "{}")'.format(each_bucket)
            rs = self.query_api.query(q)
            measurements_list = [(_m.values['_value']) for _m in rs[0].records]

            def m_dict(m):
                d = dict()
                d['bucket'] = each_bucket
                d['mangled_bucket'] = mangle_bucket_name(each_bucket)
                d['mangled_measurement'] = mangle_measurement_name(m)
                d['mangled_path'] = bucket_name__measurement_name(each_bucket, m)
                d['fields'] = self.fields(each_bucket, m)
                return d
            measurements.extend(m_dict(m) for m in measurements_list)
        return measurements

    @property
    def databases(self):
        rs = self.client.get_list_database()
        return iter(rs)


def gen_entity_set_xml(m):
    return '<EntitySet Name="{}" EntityType="InfluxDBSchema.{}"/>'.format(m['mangled_path'], m['mangled_path'])


def generate_properties_xml(m):
    return '\n'.join(
        '<Property Name="{}" Type="{}" Nullable="true" />'.format(f['name'], f['edm_type']) for f in m['fields']
    )


def generate_key_xml(m):
    """influxdb has no concept of a key, so we use the time value (NOT gauranteed to be unique)"""
    return '<Key><PropertyRef Name="timestamp" /></Key>' \
           '<Property Name="timestamp" Type="Edm.DateTime" Precision="6" Nullable="false" />'


def gen_entity_type_xml(m):
    return '<EntityType Name="{}">{}\n{}</EntityType>'.format(
        m['mangled_path'],
        generate_key_xml(m),
        generate_properties_xml(m))


def entity_sets_and_types(db):
    """generate xml entries for entity sets (containers) and entity types (with properties)"""
    entity_sets = []
    entity_types = []
    for m in db.measurements:
        entity_sets.append(gen_entity_set_xml(m))
        entity_types.append(gen_entity_type_xml(m))
    return entity_sets, entity_types


def generate_metadata(connection):
    """connect to influxdb, read the structure, and return an edmx xml file string"""
    i = InfluxDB(connection)
    entity_sets, entity_types = entity_sets_and_types(i)
    output = """{}
    <EntityContainer Name="InfluxDB" m:IsDefaultEntityContainer="true">
    {}
    </EntityContainer>
    {}
    {}""".format(xml_head, '\n'.join(entity_sets), '\n'.join(entity_types), xml_foot)
    return output
