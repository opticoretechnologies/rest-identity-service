package com.opticoretechnologies.rest.identity.service;


import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.stereotype.Service;



@Service
public class TokenHashingService {

    public String hashToken(String rawToken){

      return   DigestUtils.sha256Hex(rawToken);
    }
}
