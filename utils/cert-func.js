(() => {                
  
  async function GetCertInfo(certIndex) {
      let responseData = await ReadCertByIndexFunction2(certIndex);    
  }
    

    document.getElementById('get_Cert_ByIndex_button').addEventListener("click", () => {
      console.log("1");
      let certIndex = document.getElementById('target_cert_index').value;
      GetCertInfo(certIndex);       
    });                         
  

})();
