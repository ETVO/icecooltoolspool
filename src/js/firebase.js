// Import the functions you need from the SDKs you need
import { initializeApp } from "firebase/app";
import { getAnalytics } from "firebase/analytics";
// TODO: Add SDKs for Firebase products that you want to use
// https://firebase.google.com/docs/web/setup#available-libraries

// Your web app's Firebase configuration
// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyAiWAmm6mP2__jc1BtY_aCgJ70u0QpmYcM",
  authDomain: "icecooltoolspool.firebaseapp.com",
  projectId: "icecooltoolspool",
  storageBucket: "icecooltoolspool.appspot.com",
  messagingSenderId: "388276006238",
  appId: "1:388276006238:web:5feeb5742b5efe7cf4f3cf",
  measurementId: "G-38SQ2VPFFE"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const analytics = getAnalytics(app);