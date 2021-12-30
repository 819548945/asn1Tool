// pkcs#7 item resolution
// create by lich<liuchao_@outlook.com>
(typeof define != 'undefined' ? define : function (factory) { 'use strict';
    if (typeof module == 'object') module.exports = factory(function (name) { return require(name); });
    else window.PKCS7Tool = factory(function (name) { return window[name.substring(2)]; });
})(function (require) {
"use strict";
    var ASN1 = require('./asn1'),
    BaseTool= require('./BaseTool'),
    Hex = require('./hex'),
    Int10 = require('./int10'),
    oids = require('./oids'),
    Base64= require('./base64')
    X509CertificateTool=require('./X509CertificateTool') ;
    function PKCS7Tool(base64){
        try {
           this.asn1=ASN1.decode(base64);
           this.base64=Base64.encode(base64);
           this.type=BaseTool.parseOID(BaseTool.getData(this.asn1.sub[0]));
        } catch (error) {
            console.log(error)
            throw "当前文件不是PKCS#7";
        }
       
    };
    PKCS7Tool.loadPKCS7=function(base64){
        if("string" == typeof base64){
            base64=base64.replace(/[\r\n]/g,'');
            var cert0= Base64.decode(base64);
            try {
                var cert=bytesToString(cert0)
                if(cert.indexOf("-----BEGIN PKCS7-----")!=-1){
                    cert=cert.replace("-----BEGIN PKCS7-----", "").replace("-----END PKCS7-----","").replace(/[\r\n]/g,'');
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
        return new PKCS7Tool(base64);       
    }
    PKCS7Tool.prototype.getBase64=function(){
        return this.base64;
    }

    PKCS7Tool.prototype.getType=function(){
       return this.type;
    }
    PKCS7Tool.prototype.getCertificateChain=function(){
        if(this.type!='signedData')throw "不是有效的p7b格式";
        var chain=this.asn1.sub[1].sub[0].sub[3].sub;
        var certificateChain=[];
        for(var i=0;i<chain.length;i++){
            certificateChain.push(new X509CertificateTool(BaseTool.toBytes(chain[i])));
        }
        return certificateChain;
    }
    PKCS7Tool.prototype.getCertificate=function(){
        if(this.type!='signedData')throw "不是有效的p7b格式";
        var chain=this.asn1.sub[1].sub[0].sub[3].sub;
        return new X509CertificateTool(BaseTool.toBytes(chain[chain.length-1]))
    }

    return PKCS7Tool;
})