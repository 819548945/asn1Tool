// x.509 Certificate item resolution
// create by lich<liuchao_@outlook.com>
(typeof define != 'undefined' ? define : function (factory) { 'use strict';
    if (typeof module == 'object') module.exports = factory(function (name) { return require(name); });
    else window.X509CertificateTool = factory(function (name) { return window[name.substring(2)]; });
})(function (require) {
"use strict";
    var ASN1 = require('./asn1'),
    Hex = require('./hex'),
    Int10 = require('./int10'),
    oids = require('./oids'),
    Base64= require('./base64');
    function X509CertificateTool(base64){
        try {
            this.asn1=ASN1.decode(base64);
            var pktype= parseOID(getData(this.asn1.sub[0].sub[6].sub[0].sub[0]));
          //  if(!(pktype=="ecPublicKey"||pktype=="rsaEncryption"))
           //     throw "当前文件不是公钥证书";
            this.base64=base64Encode(base64);
        } catch (error) {
            throw "当前文件不是公钥证书";
        }
       
    };
    X509CertificateTool.loadX509Certificate=function(base64){
        if("string" == typeof base64){
            base64=base64.replace(/[\r\n]/g,'');
            var cert0= Base64.decode(base64);  
            try {
                var cert=bytesToString(cert0)
                if(cert.indexOf("-----BEGIN CERTIFICATE-----")!=-1){
                    cert=cert.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----","").replace(/[\r\n]/g,'');
                    base64=Base64.decode(cert);
                }else{
                   try {
                    base64=Base64.decode(cert);
                   } catch (error) {
                    base64=cert0;
                   }
                }
            } catch (error) {
                base64=cert0;
            }
        }
       return new X509CertificateTool(base64)     
    };
    X509CertificateTool.prototype.getBase64=function(){
        return this.base64;
    }
    X509CertificateTool.prototype.getSerial=function(){ 
       return Hex.encode(getData(this.asn1.sub[0].sub[1]));
    };
    X509CertificateTool.prototype.getSubject=function(){
       var dns=this.asn1.sub[0].sub[5].sub;
       var sdn="";
       for(var i=0;i<dns.length;i++)
       sdn+=","+parseOID(getData(dns[i].sub[0].sub[0]))+"="+bytesToString(getData(dns[i].sub[0].sub[1]));
       sdn= sdn.substr(1);
       return sdn;
    };
    X509CertificateTool.prototype.getIssuer=function(){
        var dns=this.asn1.sub[0].sub[3].sub;
        var sdn="";
        for(var i=0;i<dns.length;i++)
        sdn+=","+parseOID(getData(dns[i].sub[0].sub[0]))+"="+bytesToString(getData(dns[i].sub[0].sub[1]));
        sdn= sdn.substr(1);
        return sdn;
    }
    X509CertificateTool.prototype.getNotBefore=function(){
       var time= bytesToString(getData(this.asn1.sub[0].sub[4].sub[0]))
       return   new Date(parseTime (time,time.length<=13)).getTime()
    }
    X509CertificateTool.prototype.getNotAfter=function(){
        var time= bytesToString(getData(this.asn1.sub[0].sub[4].sub[1]))
        return   new Date(parseTime (time,time.length<=13)).getTime()
    };
    X509CertificateTool.prototype.getAlgorithm=function(){
        var sub=this.asn1.sub[0].sub[2].sub;
        return parseOID(getData(sub[0]))
    };
    function getData(node){
        var db=node.stream.pos+node.header;
        var de=db+node.length;
        var ret=[];
        for(var i=db,j=0;i<de;i++,j++)
            ret[j]=node.stream.enc[i];
        return ret;
    };
    X509CertificateTool.bytesToString=bytesToString;
    function bytesToString(arr) {
        if(typeof arr === 'string') {
            return arr;
        }
        var str = '',
            _arr = arr;
        for(var i = 0; i < _arr.length; i++) {
            var one = _arr[i].toString(2),
                v = one.match(/^1+?(?=0)/);
            if(v && one.length == 8) {
                var bytesLength = v[0].length;
                var store = _arr[i].toString(2).slice(7 - bytesLength);
                for(var st = 1; st < bytesLength; st++) {
                    store += _arr[st + i].toString(2).slice(2);
                }
                str += String.fromCharCode(parseInt(store, 2));
                i += bytesLength - 1;
            } else {
                str += String.fromCharCode(_arr[i]);
            }
        }
        return str;
    };
    function parseOID(bytes) {
        var s = '',
            n = new Int10(),
            bits = 0;
           
        for (var i = 0; i < bytes.length; ++i) {
            var v = bytes[i]; 
            n.mulAdd(128, v & 0x7F); 
            bits += 7;
            if (!(v & 0x80)) { // finished
                if (s === '') {
                    n = n.simplify();
                    if (n instanceof Int10) {
                        n.sub(80);
                        s = "2." + n.toString();
                    } else {
                        var m = n < 80 ? n < 40 ? 0 : 1 : 2;
                        s = m + "." + (n - m * 40);
                    }
                } else
                    s += "." + n.toString();
                n = new Int10();
                bits = 0;
            }
        }
        if (bits > 0)
            s += ".incomplete";
        if (typeof oids === 'object') {
            var oid = oids[s];
            if (oid) {
                if (oid.c1) s =oid.c1;
                else if (oid.d) s = oid.d;
            }
        }
        return s;
    };
    var reTimeS =     /^(\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/,
    reTimeL = /^(\d\d\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
    function parseTime (s, shortYear) {
        var m = (shortYear ? reTimeS : reTimeL).exec(s);
        if (!m)
            return "Unrecognized time: " + s;
        if (shortYear) {
            // to avoid querying the timer, use the fixed range [1970, 2069]
            // it will conform with ITU X.400 [-10, +40] sliding window until 2030
            m[1] = +m[1];
            m[1] += (m[1] < 70) ? 2000 : 1900;
        }
        s = m[1] + "/" + m[2] + "/" + m[3] + " " + m[4];
        if (m[5]) {
            s += ":" + m[5];
            if (m[6]) {
                s += ":" + m[6];
                if (m[7])
                    s += "." + m[7];
            }
        }
        if (m[8]) {
            s += "";
            if (m[8] != 'Z') {
                s += m[8];
                if (m[9])
                    s += ":" + m[9];
            }
        }
        return s;
    };
    function base64Encode( buffer ) {
              var binary = '';
              var bytes = new Uint8Array( buffer );
              var len = bytes.byteLength;
              for (var i = 0; i < len; i++) {
                  binary += String.fromCharCode( bytes[ i ] );
              }
              return window.btoa( binary );
         }
    return X509CertificateTool;
})