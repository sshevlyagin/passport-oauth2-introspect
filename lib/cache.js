// really dumb implementation of the two Redis commands we need
module.exports = function _cache (cleanPeriod) {
  var cacheData = {};

  function cacheCleanup () {
    var now = Math.floor(Date.now()/1000);
    Object.keys(cacheData).forEach( function (key) {
      if (cacheData[key].exp < now) {
        delete cacheData[key];
      }
    });
  }
  
  if (cleanPeriod) {
    setInterval(cacheCleanup, cleanPeriod);
  }

  return {
    get: function get (key, callback) {
      var now = Math.floor(Date.now()/1000);
      if (cacheData[key] && cacheData[key].exp < now) {
        delete cacheData[key];
      }
      callback(null, cacheData[key] ? cacheData[key].data : undefined);
    },
    setex: function setex (key, timeout, data, callback) {
      var now = Math.floor(Date.now()/1000);
      cacheData[key] = {
        exp: now + timeout,
        data: data
      };
      callback(null, 'OK');
    }
  };
};