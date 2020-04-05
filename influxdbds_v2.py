import datetime
import numbers
import logging
from influxdb_client import InfluxDBClient
#from functools32 import lru_cache
from pyslet.iso8601 import TimePoint
import pyslet.rfc2396 as uri
from pyslet.odata2.core import EntityCollection, CommonExpression, PropertyExpression, BinaryExpression, \
    LiteralExpression, Operator, SystemQueryOption, format_expand, format_select, ODataURI

import sys
if sys.version_info[0] >= 3:
    unicode = str

from local_store import request

logger = logging.getLogger("odata-influxdb")

operator_symbols = {
    Operator.lt: ' < ',
    Operator.le: ' <= ',
    Operator.gt: ' > ',
    Operator.ge: ' >= ',
    Operator.eq: ' = ',
    Operator.ne: ' != ',
    getattr(Operator, 'and'): ' AND ',  # Operator.and doesn't resolve in Python
    getattr(Operator, 'or'): ' OR '
}


class InfluxDBEntityContainer(object):
    """Object used to represent an Entity Container (influxdb database)

    modelled after the SQLEntityContainer in pyslet (sqlds.py)

    container
        pyslet.odata2.csdl.EntityContainer

    connection
        dict with connection configuration
        format : {url:"http://localhost:9999", token:"my-token", org:"my-org"}
    """
    def __init__(self, container, connection, topmax, **kwargs):
        self.container = container
        try:
            self.client = InfluxDBClient(url=connection['url'], token=connection['token'], org=connection["org"])
            self.query_api = self.client.query_api()
            self._topmax = topmax

            for es in self.container.EntitySet:
                self.bind_entity_set(es)
        except Exception as e:
            logger.info("Failed to connect to initialize Influx Odata container")
            logger.exception(str(e))

    def bind_entity_set(self, entity_set):
        entity_set.bind(self.get_collection_class(), container=self)

    def get_collection_class(self):
        return InfluxDBMeasurement


# noinspection SqlDialectInspection
def unmangle_measurement_name(measurement_name):
    """corresponds to mangle_measurement_name in influxdbmeta.py"""
    measurement_name = measurement_name.replace('_sp_', ' ')
    measurement_name = measurement_name.replace('_dsh_', '-')
    return measurement_name

def unmangle_bucket_name(bucket):
    """corresponds to mangle_db_name in influxdbmeta.py"""
    if bucket == u'monitoring':
        bucket = u'_monitoring'     # to handle monitoring bucket. Bucket shouldn't start with special char
    bucket = bucket.replace('_dsh_', '-')
    return bucket

def unmangle_field_name(field_name):
    return field_name
    return field_name.replace('__', ' ').strip()

def unmangle_entity_set_name(name):
    bucket, measurement = name.split('__', 1)
    bucket = unmangle_bucket_name(bucket)
    measurement = unmangle_measurement_name(measurement)
    return bucket, measurement


def parse_influxdb_time(t_str):
    """
    returns a `datetime` object (some precision from influxdb may be lost)
    :type t_str: str
    :param t_str: a string representing the time from influxdb (ex. '2017-01-01T23:01:41.123456789Z')
    """
    try:
        return datetime.datetime.strptime(t_str[:26].rstrip('Z'), '%Y-%m-%dT%H:%M:%S.%f')
    except ValueError:
        return datetime.datetime.strptime(t_str[:19], '%Y-%m-%dT%H:%M:%S')


class InfluxDBMeasurement(EntityCollection):
    """represents a measurement query, containing points

    name should be "database.measurement"
    """
    def __init__(self, container, **kwargs):
        super(InfluxDBMeasurement, self).__init__(**kwargs)
        self.container = container
        self.bucket_name, self.measurement_name = unmangle_entity_set_name(self.entity_set.name)
        #self.bucket = "_measurement"
        self.topmax = getattr(self.container, '_topmax', 50)
        self.query_len = 10

    #@lru_cache()
    '''
    def _query_len(self):
        """influxdb only counts non-null values, so we return the count of the field with maximum non-null values"""
        q = 'from(bucket: "{}") | > range({}| > count()'.format(
            self.bucket,
            self._where_expression()
        ).strip()

        logger.info('Querying InfluxDB: {}'.format(q))
        rs = self.container.query_api.query(q)
        #rs = self.container.client.query(q)
        interval_list = list(rs.get_points())
        if request and request.args.get('aggregate'):
            max_count = len(interval_list)
        else:
            max_count = max(val for val in rs.get_points().__next__().values() if isinstance(val, numbers.Number))
        self._influxdb_len = max_count
        return max_count
    '''

    def __len__(self):
        return self.topmax    # _query_len()

    def set_expand(self, expand, select=None):
        """Sets the expand and select query options for this collection.

        The expand query option causes the named navigation properties
        to be expanded and the associated entities to be loaded in to
        the entity instances before they are returned by this collection.

        *expand* is a dictionary of expand rules.  Expansions can be chained,
        represented by the dictionary entry also being a dictionary::

                # expand the Customer navigation property...
                { 'Customer': None }
                # expand the Customer and Invoice navigation properties
                { 'Customer':None, 'Invoice':None }
                # expand the Customer property and then the Orders property within Customer
                { 'Customer': {'Orders':None} }

        The select query option restricts the properties that are set in
        returned entities.  The *select* option is a similar dictionary
        structure, the main difference being that it can contain the
        single key '*' indicating that all *data* properties are
        selected."""
        self.entity_set.entityType.ValidateExpansion(expand, select)
        self.expand = expand
        # in influxdb, you must always query at LEAST the time field
        if select is not None and 'timestamp' not in select:
            select['timestamp'] = None
        self.select = select
        self.lastEntity = None

    def expand_entities(self, entityIterable):
        """Utility method for data providers.

        Given an object that iterates over all entities in the
        collection, returns a generator function that returns expanded
        entities with select rules applied according to
        :py:attr:`expand` and :py:attr:`select` rules.

        Data providers should use a better method of expanded entities
        if possible as this implementation simply iterates through the
        entities and calls :py:meth:`Entity.Expand` on each one."""
        for e in entityIterable:
            if self.expand or self.select:
                e.Expand(self.expand, self.select)
            yield e

    def itervalues(self):
        return self.expand_entities(
            self._generate_entities())


    def _generate_entities(self):
        # SELECT_clause [INTO_clause] FROM_clause [WHERE_clause]
        # [GROUP_BY_clause] [ORDER_BY_clause] LIMIT_clause OFFSET <N> [SLIMIT_clause]

        """
        'from(bucket:"_monitoring")
        |> range(start : 2020-03-25T00:00:00Z  ,  stop : 2020-03-27T00:00:00Z)
        |> filter(fn: (r) => r._measurement == "cpu")
        |> filter(fn: (r) => r._field =~ /usage_guest|usage_guest_nice|usage_idle/)
        |> aggregateWindow(every: 1h, fn: last)
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> keep(fn: (column) => column != "_start" and column != "_stop" and column != "_measurement")
        |> limit(n:100)
        |> yield()'

        """

        q = u'from(bucket:"{}") ' \
            u'{}' \
            u'|> filter(fn: (r) => r._measurement == "{}") ' \
            u'|> filter(fn: (r) => r._field =~ /{}/) ' \
            u'{} {}' \
            u'|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")' \
            u'|> keep(fn: (column) => column != "_start" and column != "_stop" and column != "_measurement")' \
            u'{} ' \
            u'|> yield()'\
            .format(self.bucket_name,
            self._range_expression(),   # range
            self.measurement_name,
            self._select_expression(),  # filter by fields
            self._tag_filter_expression(),  # filter by tags
            self._groupBy_expression(),
            self._limit_expression()).strip()

        logger.info('Querying InfluxDB: {}'.format(q))

        result = self.container.query_api.query(q)

        for table in result:
            for record in table.records:
                record = record.values
                record.__delitem__('table')
                record.__delitem__('result')
                e = self.new_entity()
                t = record['_time']      # flux client returns datetime object, no need to format
                e["timestamp"].set_from_value(t)
                for field, value in record.items():
                    try:
                        e[field.replace(' ', '__').strip()].set_from_value(value)
                    except:
                        # in case if field in query result doesn't exists in metadata schema, SKIP the field
                        continue
                e.exists = True
                self.lastEntity = e
                yield e

    def _select_expression(self):
        # formats the list of fields and tags to be displayed

        def fetch_all_keys():
            # fetch all columns in metadata (ie schema xml). Includes both _fields and tags
            entitySet_name = str(self.get_location())
            entitySet_name = entitySet_name.split("/")[-1]
            _entityDict = getattr(self.container, '_entityDict', {})
            return _entityDict[entitySet_name]

        if self.select is None or '*' in self.select:
            return '|'.join(unmangle_field_name(str(k)) for k in fetch_all_keys())
        else:
            return '|'.join(str(k).replace('__', ' ').strip() for k in self.select.keys() if k != u'timestamp')


    def _range_expression(self):
        """generates a valid InfluxDB2 range query part from the parsed filter (set with self.set_filter)"""
        # using filter expression to define the time range of the query
        # In influx2, range query is in the format
        # range(start:2018-05-22T23:30:00Z, stop: 2018-05-23T00:00:00Z) or
        # range(start: -12h, stop: -15m)
        # with stop parameter being optional
        if self.filter is None:
            return u''
        exp = (self._sql_where_expression(self.filter)).replace('AND',',').split(',')
        return u'|> range({})'.format(u' , '.join([(i.replace('"','').replace("'",'')) for i in exp if "start" in i or "stop" in i]))

    def _tag_filter_expression(self):
        # generates tag filters
        if self.filter is None:
            return u''
        exp = (self._sql_where_expression(self.filter)).replace('AND', ',').split(',')
        tags = [(i) for i in exp if "start" not in i and "stop" not in i]
        if len(tags) == 0:
            return u''
        formatted_tags = []
        for each_tag in tags:
            l_operand = each_tag.split('=')[0].strip()
            r_operand = each_tag.split('=')[1].strip()
            formatted_tags.append(u'r.{} == "{}"'.format(l_operand, r_operand))

        # TODO : Add support for 'OR' condition if there are multiple conditions
        # currently supports only "AND: operator
        return u'|> filter(fn: (r) => {})'.format(u' and '.join(formatted_tags))

    def _sql_where_expression(self, filter_expression):
        if filter_expression is None:
            return ''
        elif isinstance(filter_expression, BinaryExpression):
            try:
                symbol = operator_symbols.get(filter_expression.operator, None)
            except:
                return ''
            l_operand = self._sql_expression(filter_expression.operands[0], symbol.strip())
            r_operand = self._sql_expression(filter_expression.operands[1], symbol.strip())
            if l_operand in ["start", "stop"]:
                return u' : '.join([l_operand, r_operand])
            else:
                return symbol.join([l_operand,r_operand])
        else:
            raise NotImplementedError

    def _sql_expression(self, expression, operator):
        if isinstance(expression, PropertyExpression):
            if expression.name == 'timestamp' or expression.name == 'time':
                # based on operator, choose start or stop parameter
                if operator in ['=', '>=', '>']:
                    return 'start'
                elif operator in ["<", "<="]:
                    return 'stop'
                else:
                    return 'null'
            return expression.name
        elif isinstance(expression, LiteralExpression):
            return self._format_literal(expression.value.value)
        elif isinstance(expression, BinaryExpression):
            return self._sql_where_expression(expression)

    def _groupBy_expression(self):
        allowed_aggregates = ['aggregateWindow', 'count', 'cov', 'covariance', 'derivative', 'difference',
                              'histogramQuantile',
                              'increase', 'integral', 'mean', 'median', 'pearsonr', 'percentile', 'skew', 'spread',
                              'stddev', 'sum']
        if request:
            groupByTime = request.args.get('groupByTime', None)
            groupByFunction = request.args.get('aggregate', None)
            # validate if the aggregate function input exists in allowed function list
            if groupByFunction is not None and len([i for i in allowed_aggregates if i in groupByFunction]) == 1:
                groupByFunction = groupByFunction.strip()
            else:
                # aggregate function defaults to last()
                groupByFunction = 'last'
            if groupByTime is None:
                return ''
            else:
                return '|> aggregateWindow(every: {}, fn: {})'.format(groupByTime, groupByFunction)
                #return '|> aggregateWindow(every: {}, fn: {})'.format(groupByTime, groupByFunction)
        else:
            return ''

    def _orderby_expression(self):
        """generates a valid InfluxDB "ORDER BY" query part from the parsed order by clause (set with self.set_orderby)"""
        return ''

    def _limit_expression(self):
        if not self.paging:
            return ''
        if not self.skip:
            return '|> limit(n:{})'.format(str(self.top))
        return '|> limit(n:{}, offset: {})'.format(str(self.top), str(self.skip))

    def _format_literal(self, val):
        if isinstance(val, unicode):
            return u"'{}'".format(val)
        elif isinstance(val, TimePoint):
            return u"'{0.date}T{0.time}Z'".format(val)
        else:
            return str(val)

    def __getitem__(self, key):
        raise NotImplementedError

    def set_page(self, top, skip=0, skiptoken=None):
        self.top = int(top or 0) or self.topmax  # a None value for top causes the default iterpage method to set a skiptoken
        self.skip = skip
        self.skiptoken = int(skiptoken or 0)
        self.nextSkiptoken = None

    def iterpage(self, set_next=False):
        """returns iterable subset of entities, defined by parameters to self.set_page"""
        if self.top == 0:  # invalid, return nothing
            return
        if self.skiptoken >= len(self):
            self.nextSkiptoken = None
            self.skip = None
            self.skiptoken = None
            return
        if self.skip is None:
            if self.skiptoken is not None:
                self.skip = int(self.skiptoken)
            else:
                self.skip = 0
        self.paging = True
        if set_next:
            # yield all pages
            done = False
            while self.skiptoken <= len(self):
                self.nextSkiptoken = (self.skiptoken or 0) + self.top
                for e in self.itervalues():
                    yield e
                self.skiptoken = self.nextSkiptoken
            self.paging = False
            self.top = self.skip = 0
            self.skiptoken = self.nextSkiptoken = None
        else:
            # yield one page
            self.nextSkiptoken = (self.skiptoken or 0) + min(len(self), self.top)
            for e in self.itervalues():
                yield e
            self.paging = False

    def get_next_page_location(self):
        """Returns the location of this page of the collection

        The result is a :py:class:`rfc2396.URI` instance."""
        token = self.next_skiptoken()
        if token is not None:
            baseURL = self.get_location()
            sysQueryOptions = {}
            if self.filter is not None:
                sysQueryOptions[
                    SystemQueryOption.filter] = unicode(self.filter)
            if self.expand is not None:
                sysQueryOptions[
                    SystemQueryOption.expand] = format_expand(self.expand)
            if self.select is not None:
                sysQueryOptions[
                    SystemQueryOption.select] = format_select(self.select)
            if self.orderby is not None:
                sysQueryOptions[
                    SystemQueryOption.orderby] = CommonExpression.OrderByToString(
                    self.orderby)
            sysQueryOptions[SystemQueryOption.skiptoken] = unicode(token)
            extraOptions = ''
            if request:
                extraOptions = u'&' + u'&'.join([
                                        u'{0}={1}'.format(k, v) for k, v in request.args.items() if k[0] != u'$'])
            return uri.URI.from_octets(
                str(baseURL) +
                "?" +
                ODataURI.format_sys_query_options(sysQueryOptions) +
                extraOptions
            )
        else:
            return None
