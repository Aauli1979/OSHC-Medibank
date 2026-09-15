package au.edu.oshc.smartguide;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@RestController @RequestMapping("/api/profile")
class ProfileController {
    final UserRepository users; final BCryptPasswordEncoder enc; final MfaService mfa; final ProgressRepository progress;
    ProfileController(UserRepository u, BCryptPasswordEncoder e, MfaService m, ProgressRepository pr){users=u;enc=e;mfa=m;progress=pr;}

    User current(HttpSession s){String e=(String)s.getAttribute("AUTH");return e==null?null:users.findByEmail(e).orElse(null);}
    ResponseEntity<?> unauthorized(){return ResponseEntity.status(401).body(Map.of("message","Authentication required."));}

    Map<String,Object> view(User u){
        return new LinkedHashMap<>(Map.of("fullName",Objects.toString(u.getFullName(),""),"userId",String.format("OSHC-%06d",u.getId()),"address",Objects.toString(u.getAddress(),""),"birthdate",Objects.toString(u.getBirthdate(),""),"phoneNumber",Objects.toString(u.getPhoneNumber(),""),"email",u.getEmail(),"photoData",Objects.toString(u.getPhotoData(),""),"mfaEnabled",u.isMfaEnabled(),"role",Objects.toString(u.getRole(),"STUDENT")));
    }

    @GetMapping ResponseEntity<?> get(HttpSession s){User u=current(s);return u==null?unauthorized():ResponseEntity.ok(view(u));}

    @PutMapping ResponseEntity<?> update(@RequestBody Map<String,Object>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized();
        u.setFullName(clean((String)b.get("fullName"),100));u.setAddress(clean((String)b.get("address"),300));u.setBirthdate(clean((String)b.get("birthdate"),20));u.setPhoneNumber(clean((String)b.get("phoneNumber"),40));
        if(b.containsKey("photoData")){String p=Objects.toString(b.get("photoData"),""); if(p.length()>3_000_000)return ResponseEntity.badRequest().body(Map.of("message","Photo is too large. Please use an image under about 2 MB."));u.setPhotoData(p);}
        users.save(u);return ResponseEntity.ok(view(u));
    }

    @PostMapping("/email") ResponseEntity<?> email(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized(); String pass=b.getOrDefault("currentPassword","");String email=b.getOrDefault("newEmail","").trim().toLowerCase();
        if(!enc.matches(pass,u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Current password is incorrect."));
        if(!email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$"))return ResponseEntity.badRequest().body(Map.of("message","Enter a valid email address."));
        if(users.findByEmail(email).filter(x->!x.getEmail().equals(u.getEmail())).isPresent())return ResponseEntity.status(409).body(Map.of("message","That email is already registered."));
        u.setEmail(email);users.save(u);s.setAttribute("AUTH",email);return ResponseEntity.ok(view(u));
    }

    @PostMapping("/password") ResponseEntity<?> password(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized();String old=b.getOrDefault("currentPassword","");String np=b.getOrDefault("newPassword","");
        if(!enc.matches(old,u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Current password is incorrect."));
        if(np.length()<12)return ResponseEntity.badRequest().body(Map.of("message","New password must be at least 12 characters."));
        u.setPasswordHash(enc.encode(np));users.save(u);return ResponseEntity.ok(Map.of("message","Password changed successfully."));
    }


    @PostMapping("/mfa/enable") ResponseEntity<?> enableMfa(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized();
        if(!enc.matches(b.getOrDefault("password",""),u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Password verification failed."));
        String secret=mfa.secret();
        s.setAttribute("MFA_ENABLE_SECRET",secret);
        s.setAttribute("MFA_ENABLE_STARTED_AT",System.currentTimeMillis());
        return ResponseEntity.ok(Map.of("otpauthUri",mfa.uri(u.getEmail(),secret),"mfaEnabled",u.isMfaEnabled()));
    }

    @PostMapping("/mfa/enable/verify") ResponseEntity<?> verifyEnableMfa(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized();
        String secret=(String)s.getAttribute("MFA_ENABLE_SECRET");
        Long started=(Long)s.getAttribute("MFA_ENABLE_STARTED_AT");
        if(secret==null || started==null || System.currentTimeMillis()-started>5*60*1000L)return ResponseEntity.status(400).body(Map.of("message","MFA setup has expired. Start setup again."));
        if(!mfa.valid(secret,b.getOrDefault("code","")))return ResponseEntity.status(400).body(Map.of("message","Invalid authenticator code."));
        u.setMfaSecret(secret);u.setMfaEnabled(true);users.save(u);
        s.removeAttribute("MFA_ENABLE_SECRET");
        s.removeAttribute("MFA_ENABLE_STARTED_AT");
        return ResponseEntity.ok(Map.of("message","MFA enabled successfully.","mfaEnabled",true));
    }

    @DeleteMapping ResponseEntity<?> deleteAccount(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized();
        if(!enc.matches(b.getOrDefault("password",""),u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Password verification failed."));
        String email=u.getEmail(); progress.findByEmail(email).ifPresent(progress::delete); users.delete(u); s.invalidate();
        return ResponseEntity.ok(Map.of("message","Account deleted successfully."));
    }

    @PostMapping("/mfa/disable") ResponseEntity<?> disableMfa(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized(); if(!enc.matches(b.getOrDefault("password",""),u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Password verification failed."));
        u.setMfaEnabled(false);users.save(u);s.invalidate();return ResponseEntity.ok(Map.of("message","MFA disabled. You must sign in again."));
    }

    @PostMapping("/mfa/reset") ResponseEntity<?> resetMfa(@RequestBody Map<String,String>b,HttpSession s){
        User u=current(s);if(u==null)return unauthorized(); if(!enc.matches(b.getOrDefault("password",""),u.getPasswordHash()))return ResponseEntity.status(400).body(Map.of("message","Password verification failed."));
        String secret=mfa.secret();u.setMfaSecret(secret);u.setMfaEnabled(false);users.save(u);s.setAttribute("PENDING",u.getEmail());s.removeAttribute("AUTH");
        return ResponseEntity.ok(Map.of("otpauthUri",mfa.uri(u.getEmail(),secret)));
    }
    String clean(String v,int max){if(v==null)return "";return v.trim().substring(0,Math.min(v.trim().length(),max));}
}
