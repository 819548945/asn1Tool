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
    Base64= require('./base64'),
    BaseTool = require('./BaseTool');
    function X509CertificateTool(base64){
        try {
            this.asn1=ASN1.decode(base64);
            var pktype= BaseTool.parseOID(BaseTool.getData(this.asn1.sub[0].sub[6].sub[0].sub[0]));
          //  if(!(pktype=="ecPublicKey"||pktype=="rsaEncryption"))
           //     throw "当前文件不是公钥证书";
            this.base64=Base64.encode(base64);
        } catch (error) {
            console.log(error);
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
       return Hex.encode(BaseTool.getData(this.asn1.sub[0].sub[1]));
    };
    X509CertificateTool.prototype.getSubject=function(){
       var dns=this.asn1.sub[0].sub[5].sub;
       var sdn="";
       for(var i=0;i<dns.length;i++)
       sdn+=","+BaseTool.parseOID(BaseTool.getData(dns[i].sub[0].sub[0]))+"="+BaseTool.bytesToString(BaseTool.getData(dns[i].sub[0].sub[1]));
       sdn= sdn.substr(1);
       return sdn;
    };
    X509CertificateTool.prototype.getIssuer=function(){
        var dns=this.asn1.sub[0].sub[3].sub;
        var sdn="";
        for(var i=0;i<dns.length;i++)
        sdn+=","+BaseTool.parseOID(BaseTool.getData(dns[i].sub[0].sub[0]))+"="+BaseTool.bytesToString(BaseTool.getData(dns[i].sub[0].sub[1]));
        sdn= sdn.substr(1);
        return sdn;
    }
    X509CertificateTool.prototype.getNotBefore=function(){
       var time= BaseTool.bytesToString(BaseTool.getData(this.asn1.sub[0].sub[4].sub[0]))
       return   new Date(BaseTool.parseTime (time,time.length<=13)).getTime()
    }
    X509CertificateTool.prototype.getNotAfter=function(){
        var time= BaseTool.bytesToString(BaseTool.getData(this.asn1.sub[0].sub[4].sub[1]))
        return   new Date(BaseTool.parseTime (time,time.length<=13)).getTime()
    };
    X509CertificateTool.prototype.getAlgorithm=function(){
        var sub=this.asn1.sub[0].sub[2].sub;
        return BaseTool.parseOID(BaseTool.getData(sub[0]))
    };
    
    X509CertificateTool.bytesToString=function(bytes){
       return BaseTool.bytesToString(bytes);
    };
   
    
    return X509CertificateTool;
})